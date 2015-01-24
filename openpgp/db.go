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

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"gopkg.in/errgo.v1"
	log "gopkg.in/hockeypuck/logrus.v0"

	"github.com/hockeypuck/hockeypuck/settings"
)

func Execv(e sqlx.Execer, query string, args ...interface{}) (sql.Result, error) {
	res, err := e.Exec(query, args...)
	if err != nil {
		log.Errorf("error executing query %q: %v", query, err)
		return nil, err
	}
	return res, nil
}

func Execf(e sqlx.Execer, query string, args ...interface{}) (sql.Result, error) {
	res, err := e.Exec(query, args...)
	if err != nil {
		log.Errorf("error executing query %q: %v", query, err)
		return nil, err
	}
	return res, nil
}

type DB struct {
	*sqlx.DB
}

func NewDB(s *settings.Settings) (*DB, error) {
	var err error
	db := &DB{}
	log.Debugf("connecting to driver=%q dsn=%q", s.OpenPGP.DB.Driver, s.OpenPGP.DB.DSN)
	db.DB, err = sqlx.Connect(s.OpenPGP.DB.Driver, s.OpenPGP.DB.DSN)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return db, nil
}

func (db *DB) CreateSchema() error {
	if err := db.CreateTables(); err != nil {
		return errgo.Mask(err)
	}
	return db.CreateConstraints()
}

func (db *DB) CreateTables() error {
	for _, crSql := range CreateTablesSql {
		log.Debug(crSql)
		_, err := Execf(db, crSql)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func (db *DB) DeleteDuplicates() error {
	for _, sql := range DeleteDuplicatesSql {
		log.Debug(sql)
		if _, err := db.Exec(sql); err != nil {
			return errgo.Mask(err)
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
			log.Debug(crSql)
			_, err := db.Exec(crSql)
			if err != nil {
				if !isDuplicateConstraint(err) {
					return errgo.Mask(err)
				} else {
					log.Debugf("ignored duplicate constraint error: %v", err)
				}
			}
		}
	}
	return nil
}

func (db *DB) DropConstraints() error {
	for _, drSqls := range DropConstraintsSql {
		for _, drSql := range drSqls {
			log.Debug(drSql)
			if _, err := db.Exec(drSql); err != nil {
				// TODO: Ignore duplicate error or check for this ahead of time
				return errgo.Mask(err)
			}
		}
	}
	return nil
}
