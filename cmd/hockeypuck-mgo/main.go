/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012  Casey Marshall

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

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"code.google.com/p/gorilla/mux"
	"launchpad.net/hockeypuck"
	. "launchpad.net/hockeypuck/cli"
	"launchpad.net/hockeypuck/mgo"
)

var mgoServer *string = flag.String("server", "localhost", "mongo server")

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

func ConnectString() string {
	return *mgoServer
}

func main() {
	var err error
	// Create an HTTP request router
	r := mux.NewRouter()
	// Create a new Hockeypuck server, bound to this router
	hkp := hockeypuck.NewHkpServer(r)
	flag.Parse()
	// Open the log
	log := OpenLog()
	// Initialize web templates
	hockeypuck.InitTemplates(*WwwRoot)
	// Resolve flags, get the database connection string
	connect := ConnectString()
	for i := 0; i < *NumWorkers; i++ {
		worker := &mgo.MgoWorker{ WorkerBase: hockeypuck.WorkerBase{ L: log } }
		err = worker.Init(connect)
		if err != nil {
			die(err)
		}
		// Start the worker
		hockeypuck.Start(hkp, worker)
	}
	// Bind the router to the built-in webserver root
	http.Handle("/", r)
	// Start the built-in webserver, run forever
	err = http.ListenAndServe(*HttpBind, nil)
	die(err)
}
