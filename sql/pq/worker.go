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
	"bytes"
	"code.google.com/p/go.crypto/openpgp/armor"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	_ "github.com/bmizerany/pq"
	"io"
	. "launchpad.net/hockeypuck"
	"strings"
)

const UUID_LEN = 43 // log(2**256, 64) = 42.666...

func NewUuid() (string, error) {
	buf := bytes.NewBuffer([]byte{})
	enc := base64.NewEncoder(base64.StdEncoding, buf)
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
	WorkerBase
	DB *sql.DB
}

func (pw *PqWorker) Init(connect string) (err error) {
	pw.WorkerBase.Init()
	pw.DB, err = sql.Open("postgres", connect)
	var count int
	if err != nil {
		pw.L.Println("connect", connect, "failed:", err)
		return
	}
	// pubkey table
	_, err = pw.DB.Exec(`
CREATE TABLE IF NOT EXISTS pubkey (
	uuid TEXT,
	fingerprint TEXT,
	key_id TEXT,
	short_id TEXT,
	algorithm INTEGER,
	key_len INTEGER,
	digest TEXT,
	content TEXT,
	PRIMARY KEY(uuid),
	UNIQUE(fingerprint),
	UNIQUE(digest))`)
	if err != nil {
		pw.L.Println("create pubkey", connect, "failed:", err)
		return
	}
	// Index on key_id
	row := pw.DB.QueryRow(`
SELECT COUNT (relname) as a FROM pg_class WHERE relname = 'pubkey_key_id_idx'`)
	err = row.Scan(&count)
	if err == nil && count == 0 {
		_, err = pw.DB.Exec(`
CREATE INDEX pubkey_key_id_idx ON pubkey(key_id)`)
		if err != nil {
			pw.L.Println("create pubkey_key_id_idx index failed:", err)
			return
		}
	}
	// Index on short_id
	row = pw.DB.QueryRow(`
SELECT COUNT (relname) as a FROM pg_class WHERE relname = 'pubkey_short_id_idx'`)
	err = row.Scan(&count)
	if err == nil && count == 0 {
		_, err = pw.DB.Exec(`
CREATE INDEX pubkey_short_id_idx ON pubkey(short_id)`)
		if err != nil {
			pw.L.Println("create pubkey_short_id_idx index failed:", err)
			return
		}
	}
	// uid table
	_, err = pw.DB.Exec(`
CREATE TABLE IF NOT EXISTS uid (
	uuid TEXT,
	key_uuid TEXT,
	keywords TEXT,
	keywords_index tsvector,
	PRIMARY KEY(uuid),
	FOREIGN KEY (key_uuid) REFERENCES pubkey(uuid))`)
	if err != nil {
		pw.L.Println("create uid failed:", err)
		return
	}
	// Create the fulltext keywords index if it doesn't exist
	row = pw.DB.QueryRow(`
SELECT COUNT (relname) as a FROM pg_class WHERE relname = 'uid_keywords_idx'`)
	err = row.Scan(&count)
	if err == nil && count == 0 {
		_, err = pw.DB.Exec(`
CREATE INDEX uid_keywords_idx ON uid USING gin(keywords_index)`)
		if err != nil {
			pw.L.Println("create uid_keywords_idx failed:", err)
		}
	}
	return
}

func (pw *PqWorker) LookupKeys(search string, limit int) (keys []*PubKey, err error) {
	rows, err := pw.DB.Query(`
SELECT k.content FROM pubkey k JOIN uid u ON (k.uuid = u.key_uuid)
WHERE u.keywords_index @@ to_tsquery($1) LIMIT $2`, search, limit)
	if err != nil {
		pw.L.Println("LookupKeys: select failed:", err)
		return
	}
	var content string
	var armorBlock *armor.Block
ROWS:
	for rows.Next() {
		if err = rows.Scan(&content); err != nil {
			return
		}
		if content == "" {
			continue
		}
		armorBlock, err = armor.Decode(bytes.NewBufferString(content))
		if err != nil {
			pw.L.Println("LookupKeys: armor decode failed:", err)
			return
		}
		keyChan, errChan := ReadKeys(armorBlock.Body)
		for {
			select {
			case key, hasKey := <-keyChan:
				if hasKey {
					keys = append(keys, key)
				} else {
					break ROWS
				}
			case _, hasErr := <-errChan:
				if !hasErr {
					break ROWS
				}
			}
		}
	}
	return
}

func (pw *PqWorker) LookupKey(keyid string) (pubkey *PubKey, err error) {
	keyid = strings.ToLower(keyid)
	var raw []byte
	raw, err = hex.DecodeString(keyid)
	if err != nil {
		pw.L.Println("LookupKey", keyid, ": decode failed:", err)
		return
	}
	// Choose column to query based on key id length
	var column string
	switch len(raw) {
	case 4:
		column = "short_id"
	case 8:
		column = "key_id"
	case 20:
		column = "fingerprint"
	default:
		return nil, InvalidKeyId
	}
	var content string
	var rows *sql.Rows
	rows, err = pw.DB.Query(fmt.Sprintf(
		`SELECT content FROM pubkey WHERE %s = $1`, column), keyid)
	if err != nil {
		pw.L.Println("LookupKey", keyid, ": select failed:", err)
		return
	}
	for rows.Next() {
		err = rows.Scan(&content)
		rows.Close()
	}
	if err != nil {
		pw.L.Println("LookupKey", keyid, ": scan failed:", err)
		return
	}
	if content == "" {
		return nil, KeyNotFound
	}
	pw.L.Println("LookupKey: matched content", len(content), "bytes")
	armorBlock, err := armor.Decode(bytes.NewBufferString(content))
	if err != nil {
		pw.L.Println("LookupKey: armor decode failed:", err)
		return
	}
	keyChan, errChan := ReadKeys(armorBlock.Body)
KEYS:
	for {
		select {
		case key, hasKey := <-keyChan:
			if key != nil {
				pubkey = key
				pw.L.Println("LookupKey: matched", key.Fingerprint)
				return
			}
			if !hasKey {
				break KEYS
			}
		case readErr, hasErr := <-errChan:
			if readErr != nil {
				pw.L.Println("LookupKey: Warning, ReadKeys error:", readErr)
			}
			if !hasErr {
				break KEYS
			}
		}
	}
	return nil, KeyNotFound
}

func (pw *PqWorker) AddKey(armoredKey string) ([]string, error) {
	pw.L.Print("AddKey(...)")
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(armoredKey))
	if err != nil {
		pw.L.Println("AddKey: armor decode failed:", err)
		return err
	}
	return pw.LoadKeys(armorBlock.Body)
}

func (pw *PqWorker) LoadKeys(r io.Reader) (fps []string, err error) {
	keyChan, errChan := ReadKeys(r)
	for {
		select {
		case key, moreKeys := <-keyChan:
			if key != nil {
				var lastKey *PubKey
				lastKey, err = pw.LookupKey(key.Fingerprint)
				if err == nil && lastKey != nil {
					pw.L.Print("Merge/Update:", key.Fingerprint)
					MergeKey(lastKey, key)
					content := bytes.NewBuffer([]byte{})
					WriteKey(content, lastKey)
					_, err = pw.DB.Exec(`UPDATE pubkey SET content = $1
WHERE fingerprint = $2`, content.String(), key.Fingerprint)
					if err != nil {
						pw.L.Println("LoadKeys: update error:", err)
					}
				} else if err == KeyNotFound {
					pw.L.Print("Insert:", key.Fingerprint)
					content := bytes.NewBuffer([]byte{})
					WriteKey(content, key)
					var key_uuid, uid_uuid string
					key_uuid, err = NewUuid()
					if err != nil {
						pw.L.Println("LoadKeys: new pubkey.uuid error:", err)
						return
					}
					_, err = pw.DB.Exec(`INSERT INTO pubkey
(uuid, fingerprint, key_id, short_id, algorithm, key_len, content) VALUES
($1, $2, $3, $4, $5, $6, $7)`, key_uuid, key.Fingerprint,
						hex.EncodeToString(key.KeyId),
						hex.EncodeToString(key.ShortId),
						key.Algorithm, key.KeyLength, content.String())
					if err != nil {
						pw.L.Println("LoadKeys: insert pubkey error:", err)
						return
					}
					for _, uid := range key.Identities {
						uid_uuid, err = NewUuid()
						if err != nil {
							pw.L.Println("LoadKeys: new uid.uuid error:", err)
							return
						}
						keywords := strings.Join(uid.Keywords, " ")
						_, err = pw.DB.Exec(`INSERT INTO uid
(uuid, key_uuid, keywords, keywords_index) VALUES
($1, $2, $3, to_tsvector($3))`, uid_uuid, key_uuid, keywords)
						if err != nil {
							pw.L.Println("LoadKeys: insert uid error:", err)
							return
						}
					}
				}
				if err != nil {
					pw.L.Println("LoadKeys error:", err)
					return
				} else {
					fps = append(fps, key.Fingerprint)
				}
			}
			if !moreKeys {
				return
			}
		case err = <-errChan:
			return
		}
	}
	panic("unreachable")
}
