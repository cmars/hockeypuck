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

func (w *Worker) CreateTables() (err error) {
	for _, crSql := range CreateTableStatements {
		w.db.Execf(crSql)
	}
	for _, alSql := range AlterTableStatements {
		if _, err := w.db.Exec(alSql); err != nil {
			// TODO: Ignore duplicate error or check for this ahead of time
			log.Println(err)
		}
	}
	return
}

func (w *Worker) CreateIndexes() (err error) {
	var count int
	row := w.db.QueryRow(IndexExists_OpenpgpUidFulltext)
	err = row.Scan(&count)
	if err == nil && count == 0 {
		w.db.Execf(CreateIndex_OpenpgpUidFulltext)
	}
	return
}
