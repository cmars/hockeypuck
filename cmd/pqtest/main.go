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
	"database/sql"
	_ "github.com/lib/pq"
	"launchpad.net/hockeypuck/sql/pq"
)

func main() {
	db, err := sql.Open("postgres", "dbname=hkp host=/var/run/postgresql sslmode=disable")
	if err != nil {
		panic(err)
	}
	pqdb := &pq.PqDb{db}
	err = pqdb.CreateTables()
	if err != nil {
		panic(err)
	}
	err = pqdb.CreateIndexes()
	if err != nil {
		panic(err)
	}
}
