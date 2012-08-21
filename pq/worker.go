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
	"crypto/sha512"
	"encoding/ascii85"
	"errors"
	"io"
	"time"
	"launchpad.net/hockeypuck"
	"bitbucket.org/cmars/go.crypto/openpgp"
	"bitbucket.org/cmars/go.crypto/openpgp/armor"
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

type keyRevision struct {
	pubKeyUuid string
	keyLogUuid string
	revision int
	armor string
}

func (pq *PqWorker) GetKey(keyid string) (string, error) {
	keyRev, err := pq.getKey(keyid)
	if err != nil {
		return "", err
	}
	return keyRev.armor, err
}

func (pq *PqWorker) getKey(keyid string) (keyRev *keyRevision, err error) {
	keyRev = &keyRevision{}
	rows, err := pq.db.Query(`SELECT pk.uuid, kl.pub_key_uuid, kl.revision, kl.armor
FROM pub_key pk JOIN key_log kl ON (pk.uuid = kl.pub_key_uuid)
WHERE pk.creation < NOW() AND (pk.expiration IS NULL OR pk.expiration > NOW())
AND kl.creation < NOW()
AND pk.state = 0
AND kl.state = 0
AND pk.fingerprint = $1
ORDER BY revision DESC
LIMIT 1`, keyid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		err = rows.Scan(&keyRev.pubKeyUuid, &keyRev.keyLogUuid, &keyRev.revision, &keyRev.armor)
	} else {
		err = hockeypuck.KeyNotFound
	}
	return
}

func (pq *PqWorker) FindKeys(search string) (uuids []string, err error) {
	rows, err := pq.db.Query(`SELECT pub_key_uuid
FROM user_id
WHERE ts @@ to_tsquery($1)
AND creation < NOW() AND expiration > NOW()
AND state = 0
ORDER BY creation DESC
LIMIT 10`, search)
	if err != nil {
		return
	}
	defer rows.Close()
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

func (pq *PqWorker) AddKey(armoredKey string) (err error) {
	// Read the keyring
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(armoredKey))
	if err != nil {
		return err
	}
	for _, entity := range entityList {
		fp := hockeypuck.Fingerprint(entity.PrimaryKey)
		last, err := pq.getKey(fp)
		if err == hockeypuck.KeyNotFound {
			// Insert new key
			return pq.insertNewKey(fp, entity, armoredKey)
		} else if err != nil {
			return err
		} else {
			// Load most recent key from armor
			lastEntityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(last.armor))
			if err != nil {
				return err
			}
			if len(lastEntityList) != 1 {
				return hockeypuck.InternalKeyInvalid
			}
			lastEntity := lastEntityList[0]
			// Merge the keyring in-place
			err = hockeypuck.MergeEntity(lastEntity, entity)
			if err != nil {
				return err
			}
			// Append new revision
			err = pq.appendKey(last, lastEntity)
			if err != nil {
				return err
			}
		}
	}
	return err
}

func (pq *PqWorker) insertNewKey(fp string, entity *openpgp.Entity, armoredKey string) (err error) {
	// Perform insertions within a transaction
	tx, err := pq.db.Begin()
	if err != nil {
		return err
	}
	// Rollback on return. No effect if commit reached.
	defer tx.Rollback()
	// Insert pub_key row
	pub_key_uuid, err := NewUuid()
	if err != nil {
		return err
	}
	now := time.Now()
	_, err = tx.Exec(`INSERT INTO pub_key (
uuid, addition, creation, expiration, state, fingerprint, algorithm, key_len) VALUES (
$1, $2, $3, $4, $5, $6, $7, $8)`,
		// TODO: openpgp needs to expose key length
		pub_key_uuid, now, entity.PrimaryKey.CreationTime, nil, 0, fp, int(entity.PrimaryKey.PubKeyAlgo), 0)
	if err != nil {
		return err
	}
	// Insert key_log row
	key_log_uuid, err := NewUuid()
	if err != nil {
		return err
	}
	armorHash := sha512.New()
	armorHash.Write([]byte(armoredKey))
	_, err = tx.Exec(`INSERT INTO key_log (
uuid, creation, state, pub_key_uuid, armor, sha512) VALUES ($1, $2, $3, $4, $5, $6)`,
		key_log_uuid, now, 0, pub_key_uuid, armoredKey, armorHash.Sum(nil))
	if err != nil {
		return err
	}
	// Insert user_id rows
	for _, uid := range entity.Identities {
		user_id_uuid, err := NewUuid()
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO user_id (
uuid, addition, creation, expiration, state, pub_key_uuid, text, ts) VALUES (
$1, $2, $3, $4, $5, $6, $7, to_tsvector('english', $7))`,
			user_id_uuid, now, uid.SelfSignature.CreationTime, nil, 0, pub_key_uuid, uid.Name)
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	return
}

func (pq *PqWorker) appendKey(last *keyRevision, nextEntity *openpgp.Entity) (err error) {
	tx, err := pq.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	key_log_uuid, err := NewUuid()
	if err != nil {
		return err
	}
	armorBuf := bytes.NewBuffer([]byte{})
	armoredWriter, err := armor.Encode(armorBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	nextEntity.Serialize(armoredWriter)
	armorHash := sha512.New()
	armorHash.Write(armorBuf.Bytes())
	_, err = tx.Exec(`INSERT INTO key_log (
uuid, creation, state, pub_key_uuid, armor, sha512) VALUES ($1, $2, $3, $4, $5, $6)`,
		key_log_uuid, now, 0, last.pubKeyUuid, string(armorBuf.Bytes()), armorHash)
	err = tx.Commit()
	return
}
