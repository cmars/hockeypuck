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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"
	"launchpad.net/hockeypuck"
	"bitbucket.org/cmars/go.crypto/openpgp"
	"bitbucket.org/cmars/go.crypto/openpgp/armor"
)

const UUID_LEN = 43  // log(2**256, 64) = 42.666...

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
	db *sql.DB
}

func NewWorker(connect string) (*PqWorker, error) {
	db, err := sql.Open("postgres", connect)
	if err != nil {
		return nil, err
	}
	return &PqWorker{ db: db }, nil
}

func (pq *PqWorker) DropTables() (err error) {
	_, err = pq.db.Exec("DROP TABLE IF EXISTS pub_key CASCADE")
	if err != nil {
		return
	}
	_, err = pq.db.Exec("DROP TABLE IF EXISTS key_log CASCADE")
	if err != nil {
		return
	}
	_, err = pq.db.Exec("DROP TABLE IF EXISTS user_id CASCADE")
	return
}

func (pq *PqWorker) CreateTables() (err error) {
	// pub_key identifies a primary public key fingerprint.
	_, err = pq.db.Exec(`CREATE TABLE IF NOT EXISTS pub_key (
	-- Primary key identifier for a public key
	uuid TEXT NOT NULL,
	-- Time when the public key was first added to this key server
	addition TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	-- Time when the public key was created
	creation TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	-- Time when the public key expires. May be NULL if no expiration
	expiration TIMESTAMP WITH TIME ZONE,
	-- Time when the public key was last modified
	modified TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	-- State of the public key. 0 is always an valid, active state
	state INT,
	-- 20-byte public key fingerprint, as a hexadecimal string
	fingerprint TEXT,
	-- Integer code representing the algorithm used for the public key
	-- as specified in RFC 4880, Section 9.1
	algorithm INT,
	-- Public key length
	key_len INT,
	-- The current public key ring, stored in binary RFC 4880 format
	key_ring BYTEA,
	-- SHA-512 message digest of the public key ring
	sha512 TEXT,
	PRIMARY KEY (uuid),
	UNIQUE (fingerprint, algorithm, key_len))
`)
	if err != nil {
		return
	}
	// user_id stores all the User ID packets associated with
	// a public key for easy searching.
	_, err = pq.db.Exec(`CREATE TABLE IF NOT EXISTS user_id (
	-- Primary key identifier for a user id
	uuid TEXT,
	-- Time when the user ID was first added to the public key on this server
	addition TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
	-- Time when the user ID was created
	creation TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	-- Time when the user ID expires. May be NULL if no expiration
	expiration TIMESTAMP,
	-- State of the public key. 0 is always an valid, active revision
	state INT DEFAULT 0 NOT NULL,
	-- Foreign-key reference to the public key of this revision
	pub_key_uuid TEXT,
	-- Text contents of the user ID. Usually 'Somebody (comment) <somebody@example.com>'
	text TEXT NOT NULL,
	-- Text-searchable content used for a full text search
	ts TSVECTOR NOT NULL,
	PRIMARY KEY (uuid),
	FOREIGN KEY (pub_key_uuid) REFERENCES pub_key (uuid))
`)
	if err != nil {
		return
	}
	// Full-text index on User ID text
	_, err = pq.db.Exec(`CREATE INDEX user_id_tsindex_idx ON user_id USING gin(ts)`)
	return
}

type keyRingResult struct {
	uuid string
	keyRing []byte
	sha512 string
}

func (pq *PqWorker) GetKey(keyid string) (string, error) {
	keyid = strings.ToLower(keyid)
	raw, err := hex.DecodeString(keyid)
	if err != nil {
		return "", hockeypuck.InvalidKeyId
	}
	switch len(raw) {
	case 4:
	case 8:
	case 20:
		;
	default:
		return "", hockeypuck.InvalidKeyId
	}
	result, err := pq.getKey(keyid)
	if err != nil {
		return "", err
	}
	armorBuf := bytes.NewBuffer([]byte{})
	armorWriter, err := armor.Encode(armorBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}
	_, err = armorWriter.Write(result.keyRing)
	if err != nil {
		return "", err
	}
	err = armorWriter.Close()
	return string(armorBuf.Bytes()), err
}

func (pq *PqWorker) getKey(keyid string) (keyRing *keyRingResult, err error) {
	keyRing = &keyRingResult{}
	rows, err := pq.db.Query(`SELECT uuid, key_ring, sha512
FROM pub_key
WHERE creation < NOW() AND (expiration IS NULL OR expiration > NOW())
AND state = 0
AND fingerprint LIKE '%' || $1`, keyid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		err = rows.Scan(&keyRing.uuid, &keyRing.keyRing, &keyRing.sha512)
	} else {
		err = hockeypuck.KeyNotFound
	}
	if rows.Next() {
		err = hockeypuck.KeyIdCollision
	}
	return
}

func (pq *PqWorker) FindKeys(search string) (uuids []string, err error) {
	rows, err := pq.db.Query(`SELECT pub_key_uuid
FROM user_id
WHERE ts @@ to_tsquery($1)
AND creation < NOW() AND (expiration IS NULL OR expiration > NOW())
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
			return pq.insertNewKey(fp, entity)
		} else if err != nil {
			return err
		} else {
			lastEntityList, err := openpgp.ReadKeyRing(bytes.NewBuffer(last.keyRing))
			if err != nil {
				return err
			}
			if len(lastEntityList) != 1 {
				return hockeypuck.InternalKeyInvalid
			}
			lastEntity := lastEntityList[0]
			// Merge the keyring in-place
			changed, err := hockeypuck.MergeEntity(lastEntity, entity)
			if err != nil {
				return err
			}
			if changed {
				// Append new revision
				err = pq.updateKey(last, lastEntity)
				if err != nil {
					return err
				}
			}
		}
	}
	return err
}

func (pq *PqWorker) insertNewKey(fp string, entity *openpgp.Entity) (err error) {
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
	keyLen, err := entity.PrimaryKey.BitLength()
	if err != nil {
		return err
	}
	keyRing := bytes.NewBuffer([]byte{})
	entity.Serialize(keyRing)
	sha512 := hockeypuck.Sha512(keyRing.Bytes())
	_, err = tx.Exec(`INSERT INTO pub_key (
uuid, creation, expiration, state, fingerprint, algorithm, key_len, key_ring, sha512) VALUES (
$1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		pub_key_uuid, entity.PrimaryKey.CreationTime, nil, 0, fp,
		int(entity.PrimaryKey.PubKeyAlgo), keyLen, keyRing.Bytes(), sha512)
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
uuid, creation, expiration, state, pub_key_uuid, text, ts) VALUES (
$1, $2, $3, $4, $5, $6, to_tsvector('english', $6))`,
			user_id_uuid, uid.SelfSignature.CreationTime, nil, 0, pub_key_uuid, uid.Name)
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	return
}

func (pq *PqWorker) updateKey(last *keyRingResult, nextEntity *openpgp.Entity) (err error) {
	tx, err := pq.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	nextKeyRing := bytes.NewBuffer([]byte{})
	nextEntity.Serialize(nextKeyRing)
	nextSha512 := hockeypuck.Sha512(nextKeyRing.Bytes())
	if nextSha512 == last.sha512 {
		// Keys match, no change
		return nil
	}
	_, err = tx.Exec(`UPDATE pub_key SET modified = $1, key_ring = $2, sha512 = $3`,
		time.Now(), nextKeyRing.Bytes(), nextSha512)
	if err != nil {
		return
	}
	err = tx.Commit()
	return
}
