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
