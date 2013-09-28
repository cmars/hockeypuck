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
	"github.com/cmars/conflux"
	"github.com/cmars/conflux/recon"
	"launchpad.net/gnuflag"
	. "launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/openpgp"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type loadCmd struct {
	configuredCmd
	path       string
	txnSize    int
	ignoreDups bool
}

func (c *loadCmd) Name() string { return "load" }

func (c *loadCmd) Desc() string { return "Load OpenPGP keyring files into database" }

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

func (c *loadCmd) Main() {
	if c.path == "" {
		Usage(c, "Load --path is required")
	}
	if c.txnSize < 1 {
		Usage(c, "Invalid --txn-size, must be >= 1")
	}
	c.configuredCmd.Main()
	InitLog()
	keys := make(chan *openpgp.Pubkey)
	hashes := make(chan *conflux.Zp)
	done := make(chan interface{})
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
	if err = ptree.Create(); err != nil {
		panic(err)
	}
	go func() {
		for {
			select {
			case z, ok := <-hashes:
				if z != nil {
					err = ptree.Insert(z)
					if err != nil {
						if c.ignoreDups && strings.Contains(err.Error(), "insert duplicate element") {
							continue
						}
						log.Printf("Error inserting %x into ptree: %v", z.Bytes(), err)
						panic(err)
					}
				}
				if !ok {
					return
				}
			}
		}
	}()
	for i := 0; i < openpgp.Config().NumWorkers(); i++ {
		go func() {
			var err error
			l := openpgp.NewLoader(db)
			if _, err = l.Begin(); err != nil {
				panic(err)
			}
			nkeys := 0
			checkpoint := func() {
				if err = l.Commit(); err != nil {
					panic(err)
				}
				if _, err = l.Begin(); err != nil {
					panic(err)
				}
				fmt.Print("X")
			}
			defer func() { done <- struct{}{} }()
			defer checkpoint()
			for {
				select {
				case key, ok := <-keys:
					if key != nil {
						if err = l.InsertKey(key); err != nil {
							log.Println("Error inserting key:", key.Fingerprint(), ":", err)
						}
						nkeys++
					}
					if !ok {
						return
					}
				}
				if nkeys%c.txnSize == 0 {
					checkpoint()
				}
			}
		}()
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(err)
	}
	// Load any tables if specified
	readAllKeys(c.path, keys, hashes)
	close(hashes)
	close(keys)
	for i := 0; i < openpgp.Config().NumWorkers(); i++ {
		<-done
	}
	if err = ptree.Flush(); err != nil {
		log.Println("Flush:", err)
	}
}

func readAllKeys(path string, keys chan *openpgp.Pubkey, hashes chan *conflux.Zp) {
	keyfiles, err := filepath.Glob(path)
	if err != nil {
		die(err)
	}
	var f *os.File
	for _, keyfile := range keyfiles {
		f, err = os.Open(keyfile)
		if err != nil {
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
			keys <- keyRead.Pubkey
			digest, err := hex.DecodeString(keyRead.Pubkey.Md5)
			if err != nil {
				log.Println("bad digest:", keyRead.Pubkey.Md5)
				continue
			}
			digest = append(digest, byte(0))
			digestZp := conflux.Zb(conflux.P_SKS, digest)
			hashes <- digestZp
		}
	}
}
