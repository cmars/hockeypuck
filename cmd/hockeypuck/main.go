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
	"launchpad.net/hockeypuck/pq"
)

var pgUser *string = flag.String("user", "", "postgres username")
var pgPass *string = flag.String("pass", "", "postgres password")
var pgHost *string = flag.String("host", "localhost", "postgres hostname")
var pgPort *int = flag.Int("port", 5432, "postgres port")
var pgDb *string = flag.String("db", "", "postgres database name")
var pgCreateTables *bool = flag.Bool("create-tables", false, "create postgres database tables")
var httpBind *string = flag.String("http", ":11371", "http bind port")

func usage() {
	if *pgUser == "" {
		fmt.Fprintf(os.Stderr, "Missing required flag: -user\n")
	}
	if *pgDb == "" {
		fmt.Fprintf(os.Stderr, "Missing required flag: -db\n")
	}
	flag.PrintDefaults()
	os.Exit(1)
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err.Error())
	os.Exit(1)
}

func ConnectString() string {
	switch {
	case *pgUser == "":
		usage()
	case *pgDb == "":
		usage()
	}
	return fmt.Sprintf("user=%s dbname=%s password=%s hostname=%s port=%d",
		*pgUser, *pgDb, *pgPass, *pgHost, *pgPort)
}

func main() {
	// Create an HTTP request router
	r := mux.NewRouter()
	// Create a new Hockeypuck server, bound to this router
	hkp := hockeypuck.NewHkpServer(r)
	flag.Parse()
	// Resolve flags, get the database connection string
	connect := ConnectString()
	// Create the worker
	worker, err := pq.NewWorker(hkp, connect)
	if err != nil {
		die(err)
	}
	// Create tables if specified
	if *pgCreateTables {
		err := worker.CreateTables()
		if err != nil {
			die(err)
		}
		os.Exit(0)
	}
	// Start the worker
	worker.Start()
	// Bind the router to the built-in webserver root
	http.Handle("/", r)
	// Start the built-in webserver, run forever
	err = http.ListenAndServe(*httpBind, nil)
	if err != nil {
		die(err)
	}
}
