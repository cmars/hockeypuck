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
	"crypto/rand"
	"encoding/ascii85"
	"errors"
	"fmt"
	"io"
	"launchpad.net/hockeypuck"
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
	for readKey := range ReadKeys(armorBlock.Body) {
		if readKey.Error != nil {
			readErrors = append(readErrors, readKey)
		} else {
			change := w.UpsertKey(readKey.Pubkey)
			changes = append(changes, change)
		}
	}
	a.Response() <- &AddResponse{Changes: changes, Errors: readErrors}
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
	change = &KeyChange{Fingerprint: key.Fingerprint(), Type: KeyChangeInvalid}
	lastKey, err := w.LookupKey(key.Fingerprint())
	if err == hockeypuck.ErrKeyNotFound {
		change.PreviousMd5 = ""
		change.PreviousSha256 = ""
		change.CurrentMd5 = key.Md5
		change.CurrentSha256 = key.Sha256
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
	log.Println(change)
	return
}

func (w *Worker) UpdateKey(pubkey *Pubkey) error {
	panic("not impl yet")
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
	var signable PacketRecord
	err := pubkey.Visit(func(rec PacketRecord) error {
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
			if _, err := w.db.Execv(`
INSERT INTO openpgp_subkey (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, algorithm, bit_len)
VALUES (
	$1, $2, $3, $4, $5,
	$6, $7, $8)`,
				r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
				pubkey.RFingerprint, r.Algorithm, r.BitLen); err != nil {
				return err
			}
			signable = r
		case *UserId:
			if _, err := w.db.Execv(`
INSERT INTO openpgp_uid (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, keywords, keywords_fulltext)
VALUES (
	$1, $2, $3, $4, $5,
	$6, $7, to_tsvector($7))`,
				r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
				pubkey.RFingerprint, r.Keywords); err != nil {
				return err
			}
			signable = r
			if pubkey.PrimaryUid == r.ScopedDigest {
				if _, err := w.db.Execv(`
UPDATE openpgp_pubkey SET primary_uid = $1 WHERE uuid = $2`,
					r.ScopedDigest, pubkey.RFingerprint); err != nil {
					return err
				}
			}
		case *UserAttribute:
			if _, err := w.db.Execv(`
INSERT INTO openpgp_uat (
	uuid, creation, expiration, state, packet,
	pubkey_uuid)
VALUES (
	$1, $2, $3, $4, $5,
	$6)`,
				r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
				pubkey.RFingerprint); err != nil {
				return err
			}
			signable = r
			if pubkey.PrimaryUat == r.ScopedDigest {
				if _, err := w.db.Execv(`
UPDATE openpgp_pubkey SET primary_uat = $1 WHERE uuid = $2`,
					r.ScopedDigest, pubkey.RFingerprint); err != nil {
					return err
				}
			}
		case *Signature:
			if _, err := w.db.Execv(`
INSERT INTO openpgp_sig (
	uuid, creation, expiration, state, packet,
	sig_type, signer, signer_uuid)
VALUES (
	$1, $2, $3, $4, $5,
	$6, $7, (SELECT uuid FROM openpgp_pubkey WHERE uuid LIKE $7 || '________________________'))`,
				r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
				r.SigType, r.RIssuerKeyId); err != nil {
				return err
			}
			sigRelationUuid, err := NewUuid()
			if err != nil {
				return err
			}
			switch signed := signable.(type) {
			case *Pubkey:
				if _, err := w.db.Execv(`
INSERT INTO openpgp_pubkey_sig (uuid, pubkey_uuid, sig_uuid)
VALUES ($1, $2, $3)`,
					sigRelationUuid, signed.RFingerprint, r.ScopedDigest); err != nil {
					return err
				}
				if r.ScopedDigest == signed.RevSigDigest {
					if _, err := w.db.Execv(`
UPDATE openpgp_pubkey SET revsig_uuid = $1 WHERE uuid = $2`,
						r.ScopedDigest, signed.RFingerprint); err != nil {
						return err
					}
				}
			case *UserId:
				if _, err := w.db.Execv(`
INSERT INTO openpgp_uid_sig (uuid, pubkey_uuid, uid_uuid, sig_uuid)
VALUES ($1, $2, $3, $4)`,
					sigRelationUuid, pubkey.RFingerprint,
					signed.ScopedDigest, r.ScopedDigest); err != nil {
					return err
				}
				if r.ScopedDigest == signed.RevSigDigest {
					if _, err := w.db.Execv(`
UPDATE openpgp_uid SET revsig_uuid = $1 WHERE uuid = $2`,
						r.ScopedDigest, signed.ScopedDigest); err != nil {
						return err
					}
				}
			case *UserAttribute:
				if _, err := w.db.Execv(`
INSERT INTO openpgp_uat_sig (uuid, pubkey_uuid, uat_uuid, sig_uuid)
VALUES ($1, $2, $3, $4)`,
					sigRelationUuid, pubkey.RFingerprint,
					signed.ScopedDigest, r.ScopedDigest); err != nil {
					return err
				}
				if r.ScopedDigest == signed.RevSigDigest {
					if _, err := w.db.Execv(`
UPDATE openpgp_uat SET revsig_uuid = $1 WHERE uuid = $2`,
						r.ScopedDigest, signed.ScopedDigest); err != nil {
						return err
					}
				}
			case *Subkey:
				if _, err := w.db.Execv(`
INSERT INTO openpgp_subkey_sig (uuid, pubkey_uuid, subkey_uuid, sig_uuid)
VALUES ($1, $2, $3, $4)`,
					sigRelationUuid, pubkey.RFingerprint,
					signed.RFingerprint, r.ScopedDigest); err != nil {
					return err
				}
				if r.ScopedDigest == signed.RevSigDigest {
					if _, err := w.db.Execv(`
UPDATE openpgp_subkey SET revsig_uuid = $1 WHERE uuid = $2`,
						r.ScopedDigest, signed.RFingerprint); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		w.db.Execv("ROLLBACK")
	} else {
		w.db.Execv("COMMIT")
	}
	return err
}
