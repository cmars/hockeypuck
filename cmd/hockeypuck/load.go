/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

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
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/conflux.v2"
	"gopkg.in/hockeypuck/conflux.v2/recon"
	log "gopkg.in/hockeypuck/logrus.v0"
	"launchpad.net/gnuflag"

	"github.com/hockeypuck/hockeypuck/openpgp"
)

type loadCmd struct {
	configuredCmd
	path            string
	txnSize         int
	ignoreDups      bool
	verifyRoundTrip bool

	db    *openpgp.DB
	w     *openpgp.Worker
	ptree recon.PrefixTree
	nkeys int
	tx    *sqlx.Tx
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
	flags.BoolVar(&cmd.verifyRoundTrip, "verify-round-trip", false, "Fetch key after insert and verify digest (slow)")
	cmd.flags = flags
	return cmd
}

func (ec *loadCmd) Main() error {
	if ec.path == "" {
		return newUsageError(ec, "--path is required")
	}
	if ec.verifyRoundTrip {
		ec.txnSize = 1
	}
	if ec.txnSize < 1 {
		return newUsageError(ec, "invalid --txn-size, must be >= 1")
	}
	err := ec.configuredCmd.Main()
	if err != nil {
		return errgo.Mask(err)
	}
	ec.db, err = openpgp.NewDB(ec.settings)
	if err != nil {
		return errgo.Mask(err)
	}
	ec.w = &openpgp.Worker{Loader: openpgp.NewLoader(ec.db, true)}
	// Ensure tables all exist
	err = ec.db.CreateTables()
	if err != nil {
		return errgo.Mask(err)
	}
	ec.ptree, err = openpgp.NewSksPTree(ec.settings)
	if err != nil {
		return errgo.Mask(err)
	}
	// Create the prefix tree (if not exists)
	err = ec.ptree.Create()
	if err != nil {
		return errgo.Mask(fmt.Errorf("Unable to create prefix tree: %v", err))
	}
	// Ensure tables all exist
	err = ec.db.CreateTables()
	if err != nil {
		return errgo.Mask(fmt.Errorf("Unable to create database tables: %v", err))
	}
	// Load all keys from input material
	ec.loadAllKeys(ec.path)
	// Close the prefix tree
	err = ec.ptree.Close()
	if err != nil {
		log.Warnf("error closing ptree: %v", err)
	}
	// Close the database connection
	err = ec.db.Close()
	if err != nil {
		log.Warnf("error closing database: %v", err)
	}
	return nil
}

func (ec *loadCmd) flushDb() error {
	if ec.tx != nil {
		if !ec.verifyRoundTrip {
			log.Infof("loaded %d keys", ec.nkeys)
		}
		err := ec.tx.Commit()
		if err != nil {
			return errgo.NoteMask(err, "failed to commit transaction")
		}
		ec.tx = nil
		ec.nkeys = 0
	}
	return nil
}

func (ec *loadCmd) insertKey(keyRead *openpgp.ReadKeyResult) error {
	var err error
	if ec.tx == nil {
		ec.tx, err = ec.w.Begin()
		if err != nil {
			return errgo.Mask(fmt.Errorf("Error starting new transaction: %v", err))
		}
	} else if ec.nkeys%ec.txnSize == 0 {
		ec.flushDb()
		ec.tx, err = ec.w.Begin()
		if err != nil {
			return errgo.Mask(fmt.Errorf("Error starting new transaction: %v", err))
		}
	}
	// Load key into relational database
	err = ec.w.InsertKeyTx(ec.tx, keyRead.Pubkey)
	if err != nil {
		log.Println("Error inserting key:", keyRead.Pubkey.Fingerprint(), ":", err)
		if _, ok := err.(pq.Error); ok {
			return errgo.Mask(fmt.Errorf("Unable to load due to database errors."))
		}
	}
	ec.nkeys++

	if ec.verifyRoundTrip {
		ec.flushDb()
		loadKey := keyRead.Pubkey
		loadDigest := openpgp.SksDigest(loadKey, md5.New())
		if loadKey.Md5 != loadDigest {
			log.Println("RTC: loaded key", loadKey.Md5, "!=", "recalculated", loadDigest)
		}
		checkKey, err := ec.w.FetchKey(loadKey.RFingerprint)
		if err != nil {
			log.Println("RTC: check failed for", loadKey.Fingerprint(), ":", err)
			return err
		}
		checkDigest := openpgp.SksDigest(checkKey, md5.New())
		if checkKey.Md5 != checkDigest {
			log.Println("RTC: check key", checkKey.Md5, "!=", "recalculated", checkDigest)
		}
		if loadKey.Md5 != checkKey.Md5 {
			log.Println("RTC: load key", loadKey.Md5, "!=", "check key", checkKey.Md5)
		}
	}
	return err
}

func (ec *loadCmd) loadAllKeys(path string) error {
	keyfiles, err := filepath.Glob(path)
	if err != nil {
		return errgo.Mask(err)
	}
	for _, keyfile := range keyfiles {
		var f *os.File
		f, err = os.Open(keyfile)
		if err != nil {
			log.Println("Failed to open", keyfile, ":", err)
			continue
		}
		defer f.Close()
		log.Infof("loading keys from %q", keyfile)
		defer ec.flushDb()
		for keyRead := range openpgp.ReadKeys(f) {
			if keyRead.Error != nil {
				log.Warnf("error reading key: %v", keyRead.Error)
				continue
			}
			digest, err := hex.DecodeString(keyRead.Pubkey.Md5)
			if err != nil {
				log.Warnf("bad digest: %q", keyRead.Pubkey.Md5)
				continue
			}
			digest = recon.PadSksElement(digest)
			digestZp := conflux.Zb(conflux.P_SKS, digest)
			err = ec.ptree.Insert(digestZp)
			if err != nil {
				log.Errorf("failed to insert digest %q into prefix tree: %v", keyRead.Pubkey.Md5, err)
				continue
			}
			err = ec.insertKey(keyRead)
			if err != nil {
				log.Errorf("failed to insert key %q into database: %v ", keyRead.Pubkey.Md5, err)
				// Attempt to remove digest from ptree, since it was not successfully loaded
				ec.ptree.Remove(digestZp)
				continue
			}
		}
	}
	return nil
}
