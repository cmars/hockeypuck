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

package pq

import (
	_ "github.com/bmizerany/pq"
	"database/sql"
	"bytes"
	"crypto/rand"
	"encoding/ascii85"
	"errors"
	"fmt"
	"io"
)

const UUID_LEN = 20

func NewUuid() (string, error) {
	buf := bytes.NewBuffer([]byte{})
	enc := ascii85.NewEncoder(buf)
	n, err := io.CopyN(enc, rand.Reader, UUID_LEN)
	if err != nil {
		return "", err
	}
	if n < UUID_LEN {
		return "", errors.New("Failed to generate UUID")
	}
	return string(buf.Bytes()), nil
}

type PqWorker struct {
	db *sql.DB
}

func NewWorker(connect string) (*PqWorker, error) {
	db, err := sql.Open("postgres", connect)
	if err != nil {
		return nil, err
	}
	return &PqWorker{ db: db }, nil
}

func (pq *PqWorker) GetKey(keyid string) (armor string, err error) {
	row := pq.db.QueryRow(fmt.Sprintf(`SELECT kl.armor
FROM pub_key pk JOIN key_log kl ON (pk.uuid = kl.pub_key_uuid)
WHERE pk.creation < NOW() AND pk.expiration > NOW()
AND kl.creation < NOW()
AND pk.state = 0
AND kl.state = 0
AND pk.fingerprint = '%s'
ORDER BY revision DESC
LIMIT 1`, keyid))
	if err != nil {
		return "", err
	}
	err = row.Scan(&armor)
	if err != nil {
		return "", err
	}
	return
}

func (pq *PqWorker) FindKeys(search string) (uuids []string, err error) {
	rows, err := pq.db.Query(`SELECT pub_key_uuid
FROM user_id
WHERE ts @@ to_tsquery(?)
AND creation < NOW() AND expiration > NOW()
AND state = 0
ORDER BY creation DESC
LIMIT 10`, search)
	uuids = []string{}
	var uuid string
	for rows.Next() {
		err = rows.Scan(&uuid)
		if err != nil {
			return
		}
		uuids = append(uuids, uuid)
	}
	return
}

func (pq *PqWorker) AddKey(armor string) (err error) {
	// Read the keyring
	// Fetch the latest key from the database
	// Compare hashes, return if the same
	// Load keyrings
	// Merge keyrings to a new revision
	// Render to ASCII-armor
	// Insert a new key_log revision
	panic("not implemented")
}
