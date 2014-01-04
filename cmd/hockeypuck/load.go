/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012, 2013  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// hockeypuck is an OpenPGP keyserver.
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cmars/conflux"
	"github.com/cmars/conflux/recon"
	"github.com/lib/pq"
	"launchpad.net/gnuflag"

	. "launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/openpgp"
)

type loadCmd struct {
	configuredCmd
	path       string
	txnSize    int
	ignoreDups bool
}

func (ec *loadCmd) Name() string { return "load" }

func (ec *loadCmd) Desc() string { return "Load OpenPGP keyring files into database" }

func newLoadCmd() *loadCmd {
	cmd := new(loadCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "Hockeypuck configuration file")
	flags.StringVar(&cmd.path, "path", "", "OpenPGP keyring file path or glob pattern")
	flags.IntVar(&cmd.txnSize, "txn-size", 5000, "Transaction size; public keys per commit")
	flags.BoolVar(&cmd.ignoreDups, "ignore-dups", false, "Ignore duplicate entries")
	cmd.flags = flags
	return cmd
}

type loadStatus struct {
	*openpgp.ReadKeyResult
	z          *conflux.Zp
	ptreeError error
	dbError    error
}

func (ec *loadCmd) Main() {
	if ec.path == "" {
		Usage(ec, "--path is required")
	}
	if ec.txnSize < 1 {
		Usage(ec, "Invalid --txn-size, must be >= 1")
	}
	ec.configuredCmd.Main()
	InitLog()
	var db *openpgp.DB
	var err error
	if db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(err)
	}
	var ptree recon.PrefixTree
	reconSettings := recon.NewSettings(openpgp.Config().Settings.TomlTree)
	if ptree, err = openpgp.NewSksPTree(reconSettings); err != nil {
		die(err)
	}
	// Create the prefix tree (if not exists)
	if err = ptree.Create(); err != nil {
		die(fmt.Errorf("Unable to create prefix tree: %v", err))
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(fmt.Errorf("Unable to create database tables: %v", err))
	}
	// Read all keys from input material
	pending := ec.readAllKeys(ec.path)
	// Try inserting into prefix tree
	ptreeLoaded, ptreeDone := ec.insertPtreeKeys(ptree, pending)
	// Keys that inserted into prefix tree are new, load into openpgp db
	dbDone := ec.insertDbKeys(db, ptreeLoaded)
	// Wait for loader to finish
	<-dbDone
	<-ptreeDone
	// Close the prefix tree
	if err = ptree.Close(); err != nil {
		log.Println("Close:", err)
	}
}

func (ec *loadCmd) insertPtreeKeys(ptree recon.PrefixTree, inStat <-chan *loadStatus) (chan *loadStatus, chan interface{}) {
	done := make(chan interface{})
	c := make(chan *loadStatus)
	go func() {
		defer close(done)
		nkeys := 0
		defer close(c)
		defer func() {
			log.Println("Loaded", nkeys, "keys into prefix tree database")
		}()
		for st := range inStat {
			if st.ReadKeyResult.Error != nil {
				continue
			}
			// Load key into prefix tree
			if st.ptreeError = ptree.Insert(st.z); st.ptreeError == nil {
				c <- st
				nkeys++
			}
		}
	}()
	return c, done
}

func (ec *loadCmd) insertDbKeys(db *openpgp.DB, inStat <-chan *loadStatus) (done chan interface{}) {
	done = make(chan interface{})
	go func() {
		defer close(done)
		var err error
		l := openpgp.NewLoader(db, true)
		if _, err = l.Begin(); err != nil {
			die(fmt.Errorf("Error starting new transaction: %v", err))
		}
		nkeys := 0
		defer func() {
			log.Println("Loaded", nkeys, "keys into OpenPGP database")
		}()
		checkpoint := func() {
			if err = l.Commit(); err != nil {
				die(fmt.Errorf("Error committing transaction: %v", err))
			}
			if _, err = l.Begin(); err != nil {
				die(fmt.Errorf("Error starting new transaction: %v", err))
			}
		}
		defer checkpoint()
		for st := range inStat {
			if st.ReadKeyResult.Error != nil {
				continue
			}
			if st.ptreeError != nil {
				continue
			}
			key := st.ReadKeyResult.Pubkey
			// Load key into relational database
			if err = l.InsertKey(key); err != nil {
				log.Println("Error inserting key:", key.Fingerprint(), ":", err)
				if _, is := err.(pq.Error); is {
					die(fmt.Errorf("Unable to load due to database errors."))
				}
			}
			nkeys++
			if nkeys%ec.txnSize == 0 {
				checkpoint()
			}
		}
	}()
	return
}

func (ec *loadCmd) readAllKeys(path string) chan *loadStatus {
	c := make(chan *loadStatus)
	keyfiles, err := filepath.Glob(path)
	if err != nil {
		die(err)
	}
	go func() {
		defer close(c)
		for _, keyfile := range keyfiles {
			var f *os.File
			if f, err = os.Open(keyfile); err != nil {
				log.Println("Failed to open", keyfile, ":", err)
				continue
			} else {
				defer f.Close()
				log.Println("Loading keys from", keyfile)
			}
			for keyRead := range openpgp.ReadKeys(f) {
				if keyRead.Error != nil {
					log.Println("Error reading key:", keyRead.Error)
					continue
				}
				digest, err := hex.DecodeString(keyRead.Pubkey.Md5)
				if err != nil {
					log.Println("bad digest:", keyRead.Pubkey.Md5)
					continue
				}
				digest = recon.PadSksElement(digest)
				digestZp := conflux.Zb(conflux.P_SKS, digest)
				c <- &loadStatus{ReadKeyResult: keyRead, z: digestZp}
			}
		}
	}()
	return c
}
