/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

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

package openpgp

import (
	"database/sql"
	"log"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

func Execv(e sqlx.Execer, query string, args ...interface{}) (sql.Result, error) {
	res, err := e.Exec(query, args...)
	if err != nil {
		log.Println(query, res, err)
	}
	return res, err
}

func Execf(e sqlx.Execer, query string, args ...interface{}) (sql.Result, error) {
	res, err := e.Exec(query, args...)
	if err != nil {
		log.Fatalln(query, res, err)
	}
	return res, err
}

type DB struct {
	*sqlx.DB
}

func NewDB() (db *DB, err error) {
	db = new(DB)
	db.DB, err = sqlx.Connect(Config().Driver(), Config().DSN())
	return
}

func (db *DB) CreateSchema() error {
	if err := db.CreateTables(); err != nil {
		return err
	}
	return db.CreateConstraints()
}

func (db *DB) CreateTables() error {
	for _, crSql := range CreateTablesSql {
		Execf(db, crSql)
	}
	return nil
}

func (db *DB) DeleteDuplicates() error {
	for _, sql := range DeleteDuplicatesSql {
		log.Println(sql)
		if _, err := db.Exec(sql); err != nil {
			return err
		}
	}
	return nil
}

func isDuplicate(err error) bool {
	if pgerr, is := err.(pq.PGError); is {
		switch pgerr.Get('C') {
		case "23000":
			return true
		case "23505":
			return true
		}
	}
	return false
}

func isDuplicateConstraint(err error) bool {
	if pgerr, is := err.(pq.PGError); is {
		switch pgerr.Get('C') {
		case "42P16":
			return true
		case "42P07":
			return true
		case "42P10":
			return true
		case "42710":
			return true
		}
	}
	return false
}

func (db *DB) CreateConstraints() error {
	for _, crSqls := range CreateConstraintsSql {
		for _, crSql := range crSqls {
			log.Println(crSql)
			if _, err := db.Exec(crSql); err != nil && !isDuplicateConstraint(err) {
				return err
			}
		}
	}
	return nil
}

func (db *DB) DropConstraints() error {
	for _, drSqls := range DropConstraintsSql {
		for _, drSql := range drSqls {
			log.Println(drSql)
			if _, err := db.Exec(drSql); err != nil {
				// TODO: Ignore duplicate error or check for this ahead of time
				log.Println(err)
			}
		}
	}
	return nil
}
