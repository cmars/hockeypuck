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

package main

import (
	"bytes"
	"code.google.com/p/gorilla/mux"
	"flag"
	"fmt"
	. "launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/mgo"
	"log"
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
	var err error
	// Create an HTTP request router
	r := mux.NewRouter()
	// Create a new Hockeypuck server, bound to this router
	hkp := NewHkpServer(r)
	flag.Parse()
	if err != nil {
		die(err)
	}
	if *configFile != "" {
		if err = LoadConfigFile(*configFile); err != nil {
			die(err)
		}
	} else {
		if err = LoadConfig(bytes.NewBuffer(nil)); err != nil {
			die(err)
		}
	}
	if *showVersion {
		fmt.Println(Version)
		os.Exit(0)
	}
	InitLog()
	// Connect to MongoDB
	client, err := mgo.NewMgoClient(mgo.MgoConfig().MgoServer())
	if err != nil {
		die(err)
	}
	// Initialize web templates
	InitTemplates(Config().Webroot())
	// Launch the request workers
	for i := 0; i < Config().NumWorkers(); i++ {
		worker := mgo.NewMgoWorker(client)
		StartWorker(hkp, worker)
	}
	// Start the PKS sync
	pksSync := &mgo.MgoPksSync{MgoClient: client}
	pksSync.Init()
	StartPksSync(pksSync)
	// Start the recon peer
	sksRecon, err := NewSksRecon(hkp)
	if err != nil {
		log.Println("Warning: Sks-compatible recon peer failed:", err)
	} else {
		sksRecon.Start()
	}
	// Bind the router to the built-in webserver root
	http.Handle("/", r)
	// Start the built-in webserver, run forever
	err = http.ListenAndServe(Config().HttpBind(), nil)
	die(err)
}
