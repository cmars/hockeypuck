package pq

import (
	"database/sql"
	_ "github.com/lib/pq"
)

type PqDb struct {
	*sql.DB
}

func (db *PqDb) CreateTables() (err error) {
	for _, crSql := range CreateTableStatements {
		if _, err = db.Exec(crSql); err != nil {
			return
		}
	}
	return
}

func (db *PqDb) CreateIndexes() (err error) {
	var count int
	row := db.QueryRow(IndexExists_OpenpgpUidFulltext)
	err = row.Scan(&count)
	if err == nil && count == 0 {
		_, err = db.Exec(CreateIndex_OpenpgpUidFulltext)
	}
	return
}
