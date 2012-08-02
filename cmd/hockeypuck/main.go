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
	"launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/noimp"
	"net/http"
)

func main() {
	// Create an HTTP request router
	r := mux.NewRouter()
	// Create a new Hockeypuck server, bound to this router
	hkp := hockeypuck.NewHkpServer(r)
	// Create a worker factory. "noimp" just responds "not implemented" for everything.
	noimp.NewWorker(hkp)
	// Bind the router to the built-in webserver root
	http.Handle("/", r)
	// Start the built-in webserver, run forever
	http.ListenAndServe(":8080", nil)
}
