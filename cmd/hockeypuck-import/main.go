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
	"flag"
	"fmt"
	"github.com/cmars/conflux"
	"github.com/cmars/conflux/recon"
	. "launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/openpgp"
	"log"
	"os"
	"path/filepath"
)

var load *string = flag.String("load", "", "Load PGP keyring filename or glob pattern")
var showVersion *bool = flag.Bool("version", false, "Display version and exit")
var configFile *string = flag.String("config", "", "Config file")
var dropIndexes *bool = flag.Bool("drop-indexes", true, "Drop constraints and indexes")
var buildIndexes *bool = flag.Bool("build-indexes", true, "Create constraints and indexes")
var dropPtree *bool = flag.Bool("drop-ptree", true, "Drop reconciliation prefix tree")
var buildPtree *bool = flag.Bool("build-ptree", true, "Build reconciliation prefix tree")
var txnSize *int = flag.Int("txn-size", 5000, "Transaction size (keys loaded per commit)")

func usage() {
	flag.PrintDefaults()
	os.Exit(1)
}

func die(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func main() {
	flag.Parse()
	var err error
	// Load Hockeypuck config file
	if *configFile != "" {
		if err = LoadConfigFile(*configFile); err != nil {
			die(err)
		}
	} else {
		// Fall back on default empty config
		SetConfig("")
	}
	if *showVersion {
		fmt.Println(Version)
		os.Exit(0)
	}
	InitLog()
	keys := make(chan *openpgp.Pubkey)
	hashes := make(chan *conflux.Zp, 15000)
	var db *openpgp.DB
	if db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	var ptree recon.PrefixTree
	reconSettings := recon.NewSettings(openpgp.Config().Settings.TomlTree)
	if ptree, err = openpgp.NewSksPTree(reconSettings); err != nil {
		die(err)
	}
	if *dropPtree {
		if err = ptree.Drop(); err != nil {
			panic(err)
		}
	}
	if *buildPtree {
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
							log.Printf("Error inserting %x into ptree: %v", z.Bytes(), err)
						}
					}
					if !ok {
						return
					}
				}
			}
		}()
	}
	for i := 0; i < openpgp.Config().NumWorkers(); i++ {
		go func() {
			l := openpgp.NewLoader(db)
			l.Begin()
			defer l.Commit()
			nkeys := 0
			var err error
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
				if nkeys%*txnSize == 0 {
					if err = l.Commit(); err != nil {
						panic(err)
					}
				}
			}
		}()
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(err)
	}
	// Drop all constraints
	if *dropIndexes {
		if err = db.DropConstraints(); err != nil {
			die(err)
		}
	}
	// Load any tables if specified
	if *load != "" {
		readAllKeys(*load, keys, hashes)
	}
	close(keys)
	close(hashes)
	// Ensure uniqueness if we dropped constraints
	if *dropIndexes {
		if err = db.DeleteDuplicates(); err != nil {
			die(err)
		}
	}
	// Create all constraints
	if *buildIndexes {
		if err = db.CreateConstraints(); err != nil {
			die(err)
		}
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
			if *buildPtree {
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
}
