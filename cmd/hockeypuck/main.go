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
	"code.google.com/p/gorilla/mux"
	"flag"
	"fmt"
	. "launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/hkp"
	"launchpad.net/hockeypuck/openpgp"
	"net/http"
	"os"
)

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
	InitTemplates()
	hkp.InitTemplates()
	// Create an HTTP request router
	r := mux.NewRouter()
	// Add common static routes
	NewStaticRouter(r)
	// Create HKP router
	hkpRouter := hkp.NewRouter(r)
	// Create SKS peer
	sksPeer, err := openpgp.NewSksPeer(hkpRouter.Service)
	// Launch the OpenPGP workers
	for i := 0; i < openpgp.Config().NumWorkers(); i++ {
		w, err := openpgp.NewWorker(hkpRouter.Service, sksPeer)
		if err != nil {
			die(err)
		}
		// Subscribe SKS to worker's key changes
		w.SubKeyChanges(sksPeer.KeyChanges)
		go w.Run()
	}
	sksPeer.Start()
	// Bind the router to the built-in webserver root
	http.Handle("/", r)
	// Start the built-in webserver, run forever
	err = http.ListenAndServe(hkp.Config().HttpBind(), nil)
	die(err)
}
