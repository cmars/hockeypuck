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

package openpgp

import (
	"log"
)

func (w *Worker) CreateSchema() (err error) {
	if err = w.CreateTables(); err != nil {
		return
	}
	return w.CreateConstraints()
}

func (w *Worker) CreateTables() (err error) {
	for _, crSql := range CreateTablesSql {
		w.db.Execf(crSql)
	}
	return
}

func (w *Worker) CreateConstraints() (err error) {
	for _, crSql := range CreateConstraintsSql {
		if _, err := w.db.Exec(crSql); err != nil {
			// TODO: Ignore duplicate error or check for this ahead of time
			log.Println(err)
		}
	}
	return
}

func (w *Worker) DropConstraints() (err error) {
	for _, drSql := range DropConstraintsSql {
		if _, err := w.db.Exec(drSql); err != nil {
			// TODO: Ignore duplicate error or check for this ahead of time
			log.Println(err)
		}
	}
	return nil
}
