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

var path *string = flag.String("path", "", "PGP keyrings to be loaded")
var showVersion *bool = flag.Bool("version", false, "Display version and exit")
var configFile *string = flag.String("config", "", "Config file")

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
	if *path == "" {
		usage()
	}
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
	for i := 0; i < openpgp.Config().NumWorkers(); i++ {
		var l *openpgp.Loader
		if l, err = openpgp.NewLoader(); err != nil {
			die(err)
		}
		go func() {
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
	readAllKeys(*path, keys)
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
