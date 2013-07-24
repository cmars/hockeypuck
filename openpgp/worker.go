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

package pq

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp/armor"
	"crypto/rand"
	"database/sql"
	"encoding/ascii85"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"io"
	. "launchpad.net/hockeypuck"
	"strings"
)

const UUID_LEN = 40 // log(2**256, 85) = 39.94...

type Worker struct {
	WorkerBase
	db *sql.DB
}

func (w *Worker) Init(connect string) (err error) {
	var count int
	w.WorkerBase.Init()
	w.db = sqlx.Connect("postgres", connect)
	if err != nil {
		log.Println("connect", connect, "failed:", err)
		return
	}
	// Create tables and indexes (idempotent).
	w.CreateTables()
	w.CreateIndexes()
	return
}

func (w *Worker) LookupKeys(search string, limit int) (keys []*PubKey, err error) {
	uuids, err := w.lookupPubkeyUuids(search, limit)
	return w.fetchKeys(uuids)
}

func (w *Worker) WriteKeys(w io.Writer, uuids []string) (err error) {
	// Stream OpenPGP packets directly out of the database,
	// in a fairly logical order.
	stmt, err = sqlx.Preparex(`
SELECT bytea FROM openpgp_pubkey pk WHERE uuid = $1 UNION
SELECT bytea FROM openpgp_sig s
	JOIN openpgp_pubkey_sig pks ON (s.uuid = pks.sig_uuid)
	WHERE pks.pubkey_uuid = $1 ORDER BY creation UNION
SELECT bytea FROM (
	SELECT bytea, 1 AS level, uuid AS subkey_uuid
		FROM openpgp_subkey sk WHERE pubkey_uuid = $1 UNION
	SELECT bytea, 2 AS level, subkey_uuid FROM openpgp_sig s
		JOIN openpgp_subkey_sig sks ON (s.uuid = sks.sig_uuid)
		WHERE sks.pubkey_uuid = $1) ORDER BY subkey_uuid, level UNION
SELECT bytea FROM (
	SELECT bytea, 1 AS level, uuid AS uid_uuid, creation
		FROM openpgp_uid u WHERE pubkey_uuid = $1 UNION
	SELECT bytea, 2 AS level, uid_uuid, creation FROM openpgp_sig s
		JOIN openpgp_uid_sig us ON (s.uuid = us.sig_uuid)
		WHERE us.pubkey_uuid = $1) ORDER BY creation, uid_uuid, level UNION
SELECT bytea FROM (
	SELECT bytea, 1 AS level, uuid AS uat, creation
		FROM openpgp_uat u WHERE pubkey_uuid = $1 UNION
	SELECT bytea, 2 AS level, uat, creation FROM openpgp_sig s
		JOIN openpgp_uat_sig uas ON (s.uuid = uas.sig_uuid)
		WHERE uas.pubkey_uuid = $1) ORDER BY creation, uat_uuid, level`)
	if err != nil {
		return
	}
	var packet struct{ data []byte }
	var rows *sqlx.Rows
	for _, uuid := range uuids {
		rows, err = stmt.Query(uuid)
		if err != nil {
			return
		}
		for rows.Next() {
			err = row.StructScan(&packet)
			if err != nil {
				return
			}
			err = w.Write(packet.data)
			if err != nil {
				return
			}
		}
	}
}

func (w *Worker) lookupPubkeyUuids(search string, limit int) (uuids []string, err error) {
	if strings.HasPrefix(search, "0x") {
		return lookupKeywordUuids(search, limit)
	}
	return lookupKeyidUuids(search)
}

func (w *Worker) lookupKeyidUuids(keyId string) (uuids []string, err error) {
	keyId = strings.ToLower(search)
	raw, err := hex.DecodeString(keyId)
	if err != nil {
		return nil, InvalidKeyId
	}
	var compareOp string
	switch len(raw) {
	case 4:
		compareOp = "LIKE '________________________________' ||"
	case 8:
		compareOp = "LIKE '________________________' ||"
	case 20:
		compareOp = "="
	default:
		return nil, InvalidKeyId
	}
	rkeyId := Reverse(keyId)
	rows, err := w.db.Queryx(fmt.Sprintf(`
SELECT uuid FROM openpgp_pubkey WHERE rfingerprint %s $1
	AND expiration > now() AND revsig_uuid IS NULL`, compareOp), rkeyId)
	if err != nil {
		return
	}
	return flattenUuidRows(rows)
}

func flattenUuidRows(rows *sqlx.Rows) (uuids []string, err error) {
	var row struct{ uuid string }
	for rows.Next() {
		err = rows.StructScan(&row)
		if err != nil {
			return
		}
		uuids = append(uuids, row.uuid)
	}
	return
}

func (w *Worker) lookupKeywordUuids(search string, limit int) (uuids []string, err error) {
	rows, err := w.db.Queryx(`
SELECT DISTINCT pk.uuid FROM openpgp_pubkey pk
	JOIN openpgp_uid u ON (pk.uuid = u.pubkey_uuid)
WHERE u.keywords_fulltext @@ to_tsquery($1)
	AND pk.expiration < now() AND pk.revsig_uuid IS NULL
	AND u.expiration < now()
	AND EXISTS (
		SELECT 1 FROM openpgp_uid_sig usig 
			JOIN openpgp_sig s ON (usig.sig_uuid = s.uuid)
		WHERE usig.uid_uuid = u.uuid AND s.expiration < now() 
			AND s.signer_uuid = pk.uuid AND sig_type BETWEEN 0x10 AND 0x13) LIMIT $2`,
		search, limit)
	if err != nil {
		return
	}
	return flattenUuidRows(rows)
}

func (w *Worker) LookupKey(keyid string) (pubkey *PubKey, err error) {
	uuids, err := w.lookupKeyidUuids(keyid)
	if err != nil {
		return nil, err
	}
	if len(uuids) < 1 {
		return nil, KeyNotFound
	}
	if len(uuids) > 1 {
		return nil, KeyIdCollision
	}
	keys, err := fetchKeys(uuids)
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		return nil, InternalKeyInvalid
	}
	return keys[0], nil
}

func (w *Worker) AddKey(armoredKey string) ([]string, error) {
	log.Print("AddKey(...)")
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(armoredKey))
	if err != nil {
		log.Println("AddKey: armor decode failed:", err)
		return err
	}
	return w.LoadKeys(armorBlock.Body)
}

func (w *Worker) LoadKeys(r io.Reader) (fps []string, err error) {
	keyChan, errChan := ReadKeys(r)
	for {
		select {
		case key, moreKeys := <-keyChan:
			if key != nil {
				err = w.upsertKey(key)
			}
			if !moreKeys {
				return
			}
		case readErr, moreErrs := <-errChan:
			err = readErr
			if !moreErrs {
				return
			}
		}
	}
	panic("unreachable")
}

func (w *Worker) UpsertKey(key *PubKey) error {
	lastKey, err := mw.LookupKey(key.Fingerprint())
	var cuml string
	var lastCuml string
	if err == nil && lastKey != nil {
		lastCuml = lastKey.Sha256()
		MergeKey(lastKey, key)
		cuml = lastKey.Sha256()
		if cuml != lastCuml {
			log.Println("Updated:", key.Fingerprint())
			lastKey.SetMtime(time.Now().UnixNano())
			err = w.UpdateKey(lastKey)
			if err == nil {
				w.modifiedKeys <- lastKey
			}
		} else {
			log.Println("Update: skipped, no change in cumulative digest")
		}
	} else if err == KeyNotFound {
		log.Println("Insert:", key.Fingerprint())
		key.Ctime = time.Now().UnixNano()
		key.Mtime = key.Ctime
		key.SksDigest = SksDigest(key)
		err = w.InsertKey(key)
		if err == nil {
			mw.createdKeys <- key
		}
	}
	if err != nil {
		log.Println("Error:", err)
		return
	}
	log.Println(key.SksDigest)
	statuses = append(statuses, &LoadKeyStatus{
		Fingerprint: key.Fingerprint(),
		Digest:      cuml,
		LastDigest:  lastCuml})
}
