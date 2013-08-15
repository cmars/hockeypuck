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
	"bytes"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/ascii85"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cmars/conflux"
	"github.com/jmoiron/sqlx"
	"io"
	. "launchpad.net/hockeypuck/errors"
	"launchpad.net/hockeypuck/hkp"
	"log"
	"time"
)

type KeyChangeChan chan *KeyChange

func (w *Worker) Add(a *hkp.Add) {
	// Parse armored keytext
	var changes []*KeyChange
	var readErrors []*ReadKeyResult
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(a.Keytext))
	if err != nil {
		a.Response() <- &ErrorResponse{err}
		return
	}
	for readKey := range ReadValidKeys(armorBlock.Body) {
		if readKey.Error != nil {
			readErrors = append(readErrors, readKey)
		} else {
			change := w.UpsertKey(readKey.Pubkey)
			w.notifyChange(change)
			changes = append(changes, change)
		}
	}
	a.Response() <- &AddResponse{Changes: changes, Errors: readErrors}
}

func (w *Worker) RecoverKey(rk *hkp.RecoverKey) {
	resp := &RecoverKeyResponse{}
	// Attempt to parse and upsert key
	var pubkeys []*Pubkey
	var err error
	for readKey := range ReadValidKeys(bytes.NewBuffer(rk.Keytext)) {
		if readKey.Error != nil {
			err = readKey.Error
		} else {
			pubkeys = append(pubkeys, readKey.Pubkey)
		}
	}
	if err == nil {
		if len(pubkeys) == 0 {
			rk.Response() <- &ErrorResponse{ErrKeyNotFound}
			return
		} else if len(pubkeys) > 1 {
			rk.Response() <- &ErrorResponse{ErrTooManyResponses}
			return
		}
		digest, err := hex.DecodeString(pubkeys[0].Md5)
		if err != nil {
			rk.Response() <- &ErrorResponse{err}
			return
		}
		resp.Change = w.UpsertKey(pubkeys[0])
		w.notifyChange(resp.Change)
		// If we arrived at the same digest as the recovery source, then we're
		// done -- Hockeypuck fully supports all the key's contents. If not, then
		// there must be some unsupported key material, so we'll continue and
		// track this so that we can fully reconcile with the recovery source.
		if rk.RecoverSet.Has(conflux.Zb(conflux.P_SKS, digest)) {
			rk.Response() <- resp
			return
		}
	}
	// Ok, we failed to read at least some of this key material.
	// Since it came from a recovery source that claims it *can* read it,
	// we'll store an unsupported record for it. Future upgrades of Hockeypuck
	// may add support for parsing and reloading it.
	var packets []*packet.OpaquePacket
	opktReader := packet.NewOpaqueReader(bytes.NewBuffer(rk.Keytext))
	for opkt, pkterr := opktReader.Next(); pkterr != io.EOF; opkt, pkterr = opktReader.Next() {
		if pkterr == nil {
			packets = append(packets, opkt)
		}
	}
	// Calculate digest
	sha256Digest := sksDigestOpaque(packets, sha256.New())
	md5Digest := sksDigestOpaque(packets, md5.New())
	resp.Change = &KeyChange{Type: KeyChangeInvalid, Fingerprint: "[cannot parse]",
		CurrentMd5: md5Digest, CurrentSha256: sha256Digest}
	// Insert unsupported record if not exists
	_, err = w.db.Execv(`
INSERT INTO openpgp_unsupp (uuid, contents, md5, source)
SELECT $1, $2, $3, $4 WHERE NOT EXISTS (
	SELECT 1 FROM openpgp_unsupp WHERE uuid = $1)`,
		sha256Digest, rk.Keytext, md5Digest, rk.Source)
	if err != nil {
		// Database communication error, yikes!
		rk.Response() <- &ErrorResponse{err}
		return
	}
	w.notifyChange(resp.Change)
	resp.Err = err
	rk.Response() <- resp
}

var ErrSubKeyChanges error = errors.New("Worker already has a key change subscriber")

func (w *Worker) SubKeyChanges(keyChanges KeyChangeChan) error {
	if w.keyChanges != nil {
		return ErrSubKeyChanges
	}
	w.keyChanges = keyChanges
	return nil
}

func (w *Worker) notifyChange(keyChange *KeyChange) {
	if w.keyChanges != nil {
		w.keyChanges <- keyChange
	}
}

type KeyChangeType int

const (
	KeyChangeInvalid KeyChangeType = iota
	KeyNotChanged    KeyChangeType = iota
	KeyAdded         KeyChangeType = iota
	KeyModified      KeyChangeType = iota
)

type KeyChange struct {
	Fingerprint    string
	CurrentMd5     string
	PreviousMd5    string
	CurrentSha256  string
	PreviousSha256 string
	Error          error
	Type           KeyChangeType
}

func (kc *KeyChange) String() string {
	w := bytes.NewBuffer(nil)
	var msg string
	switch kc.Type {
	case KeyChangeInvalid:
		msg = fmt.Sprintf("Invalid key change for [%s] could not be processed",
			kc.Fingerprint)
	case KeyAdded:
		msg = fmt.Sprintf("Add key %s, [%s..]", kc.Fingerprint, kc.CurrentSha256[:8])
	case KeyModified:
		msg = fmt.Sprintf("Modify key %s, [%s.. -> %s..]", kc.Fingerprint,
			kc.PreviousSha256[:8], kc.CurrentSha256[:8])
	case KeyNotChanged:
		msg = fmt.Sprintf("No change in key %s", kc.Fingerprint)
	}
	w.Write([]byte(msg))
	if kc.Error != nil {
		w.Write([]byte(fmt.Sprintf(": Error: %v", kc.Error)))
	}
	return w.String()
}

func (change *KeyChange) calcType() KeyChangeType {
	if change.CurrentSha256 == "" {
		return KeyChangeInvalid
	} else if change.PreviousSha256 == "" {
		return KeyAdded
	} else if change.PreviousSha256 == change.CurrentSha256 {
		return KeyNotChanged
	}
	return KeyModified
}

func (w *Worker) UpsertKey(key *Pubkey) (change *KeyChange) {
	change = &KeyChange{
		Fingerprint:   key.Fingerprint(),
		Type:          KeyChangeInvalid,
		CurrentMd5:    key.Md5,
		CurrentSha256: key.Sha256}
	lastKey, err := w.LookupKey(key.Fingerprint())
	if err == ErrKeyNotFound {
		change.Type = KeyAdded
	} else if err != nil {
		change.Error = err
		return
	} else {
		change.PreviousMd5 = lastKey.Md5
		change.PreviousSha256 = lastKey.Sha256
		MergeKey(lastKey, key)
		change.CurrentMd5 = lastKey.Md5
		change.CurrentSha256 = lastKey.Sha256
		if change.PreviousSha256 == change.CurrentSha256 {
			change.Type = KeyNotChanged
		} else {
			change.Type = KeyModified
		}
	}
	if change.CurrentSha256 == "" {
		change.Type = KeyChangeInvalid
	}
	switch change.Type {
	case KeyModified:
		lastKey.Mtime = time.Now()
		change.Error = w.UpdateKey(lastKey)
	case KeyAdded:
		key.Ctime = time.Now()
		key.Mtime = key.Ctime
		change.Error = w.InsertKey(key)
	}
	if change.Type != KeyNotChanged {
		log.Println(change)
	}
	return
}

func (w *Worker) UpdateKey(pubkey *Pubkey) error {
	tx, err := w.db.Beginx()
	if err != nil {
		return err
	}
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			if _, err := w.db.Execv(`
UPDATE openpgp_pubkey SET
	expiration = $2, state = $3, mtime = $4, md5 = $5, sha256 = $6,
	revsig_uuid = $7, primary_uid = $8, primary_uat = $9
WHERE uuid = $1`, r.RFingerprint, r.Expiration, r.State, r.Mtime, r.Md5, r.Sha256,
				r.RevSigDigest, r.PrimaryUid, r.PrimaryUat); err != nil {
				return err
			}
			signable = r
		case *Subkey:
			_, err := tx.Execv(`
UPDATE openpgp_subkey SET expiration = $2, state = $3, revsig_uuid = $4 WHERE uuid = $1`,
				r.RFingerprint, r.Expiration, r.State, r.RevSigDigest)
			if err == sql.ErrNoRows {
				err = w.insertSubkey(tx, pubkey, r)
			}
			if err != nil {
				return err
			}
			signable = r
		case *UserId:
			_, err := tx.Execv(`
UPDATE openpgp_uid SET
	creation = $2, expiration = $3, state = $4, revsig_uuid = $5 WHERE uuid = $1`,
				r.ScopedDigest, r.Creation, r.Expiration, r.State, r.RevSigDigest)
			if err == sql.ErrNoRows {
				err = w.insertUid(tx, pubkey, r)
			}
			if err != nil {
				return err
			}
			signable = r
		case *UserAttribute:
			_, err := tx.Execv(`
UPDATE openpgp_uat SET
	creation = $2, expiration = $3, state = $4, revsig_uuid = $5 WHERE uuid = $1`,
				r.ScopedDigest, r.Creation, r.Expiration, r.State, r.RevSigDigest)
			if err == sql.ErrNoRows {
				err = w.insertUat(tx, pubkey, r)
			}
			if err != nil {
				return err
			}
			signable = r
		case *Signature:
			_, err := tx.Execv(`
UPDATE openpgp_sig SET
	state = $2, signer_uuid = $3, revsig_uuid = $4 WHERE uuid = $1`,
				r.ScopedDigest, r.State, r.RIssuerFingerprint, r.RevSigDigest)
			if err == sql.ErrNoRows {
				err = w.insertSig(tx, pubkey, r)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
	return err
}

const UUID_LEN = 40 // log(2**256, 85) = 39.9413926456896

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

func (w *Worker) InsertKey(pubkey *Pubkey) error {
	tx, err := w.db.Beginx()
	if err != nil {
		return err
	}
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			if _, err := w.db.Execv(`
INSERT INTO openpgp_pubkey (
	uuid, creation, expiration, state, packet,
	ctime, mtime,
    md5, sha256, algorithm, bit_len)
VALUES (
	$1, $2, $3, $4, $5,
	now(), now(),
    $6, $7, $8, $9)`,
				r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
				// TODO: use mtime and ctime from record, or use RETURNING to set it
				r.Md5, r.Sha256, r.Algorithm, r.BitLen); err != nil {
				return err
			}
			signable = r
		case *Subkey:
			if err := w.insertSubkey(tx, pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserId:
			if err := w.insertUid(tx, pubkey, r); err != nil {
				return err
			}
			if err := w.updatePrimaryUid(tx, pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserAttribute:
			if err := w.insertUat(tx, pubkey, r); err != nil {
				return err
			}
			if err := w.updatePrimaryUat(tx, pubkey, r); err != nil {
				return err
			}
			signable = r
		case *Signature:
			if err := w.insertSig(tx, pubkey, r); err != nil {
				return err
			}
			if err := w.insertSigRelations(tx, pubkey, signable, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
	return err
}

func (w *Worker) insertSubkey(tx *sqlx.Tx, pubkey *Pubkey, r *Subkey) error {
	_, err := tx.Execv(`
INSERT INTO openpgp_subkey (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, algorithm, bit_len)
VALUES (
	$1, $2, $3, $4, $5,
	$6, $7, $8)`,
		r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.Algorithm, r.BitLen)
	return err
}

func (w *Worker) insertUid(tx *sqlx.Tx, pubkey *Pubkey, r *UserId) error {
	_, err := tx.Execv(`
INSERT INTO openpgp_uid (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, keywords, keywords_fulltext)
VALUES (
	$1, $2, $3, $4, $5,
	$6, $7, to_tsvector($7))`,
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.Keywords)
	return err
}

func (w *Worker) insertUat(tx *sqlx.Tx, pubkey *Pubkey, r *UserAttribute) error {
	_, err := tx.Execv(`
INSERT INTO openpgp_uat (
	uuid, creation, expiration, state, packet,
	pubkey_uuid)
VALUES (
	$1, $2, $3, $4, $5,
	$6)`,
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint)
	return err
}

func (w *Worker) updatePrimaryUid(tx *sqlx.Tx, pubkey *Pubkey, r *UserId) error {
	if pubkey.PrimaryUid.String == r.ScopedDigest {
		if _, err := tx.Execv(`
UPDATE openpgp_pubkey SET primary_uid = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updatePrimaryUat(tx *sqlx.Tx, pubkey *Pubkey, r *UserAttribute) error {
	if pubkey.PrimaryUat.String == r.ScopedDigest {
		if _, err := tx.Execv(`
UPDATE openpgp_pubkey SET primary_uat = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) insertSig(tx *sqlx.Tx, pubkey *Pubkey, r *Signature) error {
	_, err := tx.Execv(`
INSERT INTO openpgp_sig (
	uuid, creation, expiration, state, packet,
	sig_type, signer, signer_uuid)
SELECT $1, $2, $3, $4, $5,
	$6, $7, COALESCE($8, (
		SELECT uuid FROM openpgp_pubkey WHERE uuid LIKE $7 || '________________________'))`,
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		r.SigType, r.RIssuerKeyId, r.RIssuerFingerprint)
	// TODO: use RETURNING to update matched issuer fingerprint
	return err
}

func (w *Worker) insertSigRelations(
	tx *sqlx.Tx, pubkey *Pubkey, signable PacketRecord, r *Signature) error {

	sigRelationUuid, err := NewUuid()
	if err != nil {
		return err
	}
	// Add signature relation to other packets
	switch signed := signable.(type) {
	case *Pubkey:
		_, err = tx.Execv(`
INSERT INTO openpgp_pubkey_sig (uuid, pubkey_uuid, sig_uuid)
SELECT $1, $2, $3 WHERE NOT EXISTS (
	SELECT 1 FROM openpgp_subkey_sig WHERE pubkey_uuid = $2 AND sig_uuid = $3)`,
			sigRelationUuid, signed.RFingerprint, r.ScopedDigest)
		if err != nil {
			return err
		}
	case *Subkey:
		_, err = tx.Execv(`
INSERT INTO openpgp_subkey_sig (uuid, pubkey_uuid, subkey_uuid, sig_uuid)
SELECT $1, $2, $3, $4 WHERE NOT EXISTS (
	SELECT 1 FROM openpgp_subkey_sig
		WHERE pubkey_uuid = $2 AND subkey_uuid = $3 AND sig_uuid = $4)`,
			sigRelationUuid, pubkey.RFingerprint, signed.RFingerprint,
			r.ScopedDigest)
		if err != nil {
			return err
		}
	case *UserId:
		_, err = tx.Execv(`
INSERT INTO openpgp_uid_sig (uuid, pubkey_uuid, uid_uuid, sig_uuid)
SELECT $1, $2, $3, $4 WHERE NOT EXISTS (
	SELECT 1 FROM openpgp_uid_sig
		WHERE pubkey_uuid = $2 AND uid_uuid = $3 AND sig_uuid = $4)`,
			sigRelationUuid, pubkey.RFingerprint, signed.ScopedDigest,
			r.ScopedDigest)
		if err != nil {
			return err
		}
	case *UserAttribute:
		_, err = tx.Execv(`
INSERT INTO openpgp_uat_sig (uuid, pubkey_uuid, uat_uuid, sig_uuid)
SELECT $1, $2, $3, $4 WHERE NOT EXISTS (
	SELECT 1 FROM openpgp_uat_sig
		WHERE pubkey_uuid = $2 AND uat_uuid = $3 AND sig_uuid = $4)`,
			sigRelationUuid, pubkey.RFingerprint, signed.ScopedDigest,
			r.ScopedDigest)
		if err != nil {
			return err
		}
	}
	return nil
}
