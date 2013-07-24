package pq

import (
	"database/sql"
	_ "github.com/jmoiron/sqlx"
)

func (pw *PqWorker) CreateTables() (err error) {
	for _, crSql := range CreateTableStatements {
		sqlx.Execf(crSql)
	}
	return
}

func (pw *PqWorker) CreateIndexes() (err error) {
	var count int
	row := db.QueryRow(IndexExists_OpenpgpUidFulltext)
	err = row.Scan(&count)
	if err == nil && count == 0 {
		db.Execf(CreateIndex_OpenpgpUidFulltext)
	}
	return
}
