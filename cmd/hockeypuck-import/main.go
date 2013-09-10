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
	"flag"
	"fmt"
	. "launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/openpgp"
	"log"
	"os"
	"path/filepath"
)

var load *string = flag.String("load", "", "Load PGP keyring filename or glob pattern")
var showVersion *bool = flag.Bool("version", false, "Display version and exit")
var configFile *string = flag.String("config", "", "Config file")
var reindex *bool = flag.Bool("reindex", true, "Rebuild constraints and indexes")

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
	var db *openpgp.DB
	if db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	for i := 0; i < openpgp.Config().NumWorkers(); i++ {
		go func() {
			l := openpgp.NewLoader(db)
			var err error
			for {
				select {
				case key := <-keys:
					if err = l.InsertKey(key); err != nil {
						log.Println("Error inserting key:", key.Fingerprint(), ":", err)
					}
				}
			}
		}()
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(err)
	}
	// If we're reindexing, drop all constraints
	if *reindex {
		if err = db.DropConstraints(); err != nil {
			die(err)
		}
	}
	// Load any tables if specified
	if *load != "" {
		readAllKeys(*load, keys)
	}
	// If we're reindexing, ensure uniqueness & create all constraints
	if *reindex {
		if err = db.CreateConstraints(); err != nil {
			die(err)
		}
	}
}

func readAllKeys(path string, keys chan *openpgp.Pubkey) {
	keyfiles, err := filepath.Glob(path)
	if err != nil {
		die(err)
	}
	var f *os.File
	for i := 0; i < len(keyfiles); i++ {
		keyfile := keyfiles[i]
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
		}
	}
}
