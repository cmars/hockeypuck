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
	"code.google.com/p/gorilla/mux"
	"flag"
	"fmt"
	. "launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/mgo"
	"net/http"
	"os"
	"time"
)

var mgoServer *string = flag.String("server", "localhost", "mongo server")
var showVersion *bool = flag.Bool("version", false, "Display version and exit")

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
	hkp := NewHkpServer(r)
	ParseCfg()
	flag.Parse()
	if *showVersion {
		fmt.Println(Version)
		os.Exit(0)
	}
	// Connect to MongoDB
	connect := ConnectString()
	client, err := mgo.NewMgoClient(connect)
	if err != nil {
		die(err)
	}
	if *mgo.UpdateKeyStats {
		// Update the key status and exit
		err = client.UpdateKeysHourly(time.Unix(0, 0))
		if err != nil {
			die(err)
		}
		err = client.UpdateKeysDaily(time.Unix(0, 0))
		if err != nil {
			die(err)
		}
		os.Exit(0)
	}
	// Initialize web templates
	InitTemplates(*WwwRoot)
	// Launch the request workers
	for i := 0; i < *NumWorkers; i++ {
		worker := &mgo.MgoWorker{MgoClient: client}
		StartWorker(hkp, worker)
	}
	// Start the PKS sync
	pksSync := &mgo.MgoPksSync{MgoClient: client}
	pksSync.Init()
	StartPksSync(pksSync)
	// Bind the router to the built-in webserver root
	http.Handle("/", r)
	// Start the built-in webserver, run forever
	err = http.ListenAndServe(*HttpBind, nil)
	die(err)
}
