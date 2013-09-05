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
	"github.com/jmoiron/sqlx"
)

type Loader struct {
	db *DB
}

func NewLoader() (l *Loader, err error) {
	l = new(Loader)
	if l.db, err = NewDB(); err != nil {
		return
	}
	// Create tables and indexes (idempotent).
	if err = l.db.CreateSchema(); err != nil {
		return
	}
	// Drop constraints for bulk import.
	err = l.db.DropConstraints()
	return
}

func (l *Loader) InsertKey(pubkey *Pubkey) error {
	tx, err := l.db.Beginx()
	if err != nil {
		return err
	}
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			if _, err := l.db.Execv(`
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
			if err := l.insertSubkey(tx, pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserId:
			if err := l.insertUid(tx, pubkey, r); err != nil {
				return err
			}
			if err := l.updatePrimaryUid(tx, pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserAttribute:
			if err := l.insertUat(tx, pubkey, r); err != nil {
				return err
			}
			if err := l.updatePrimaryUat(tx, pubkey, r); err != nil {
				return err
			}
			signable = r
		case *Signature:
			if err := l.insertSig(tx, pubkey, r); err != nil {
				return err
			}
			if err := l.insertSigRelations(tx, pubkey, signable, r); err != nil {
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

func (l *Loader) insertSubkey(tx *sqlx.Tx, pubkey *Pubkey, r *Subkey) error {
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

func (l *Loader) insertUid(tx *sqlx.Tx, pubkey *Pubkey, r *UserId) error {
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

func (l *Loader) insertUat(tx *sqlx.Tx, pubkey *Pubkey, r *UserAttribute) error {
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

func (l *Loader) updatePrimaryUid(tx *sqlx.Tx, pubkey *Pubkey, r *UserId) error {
	if pubkey.PrimaryUid.String == r.ScopedDigest {
		if _, err := tx.Execv(`
UPDATE openpgp_pubkey SET primary_uid = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (l *Loader) updatePrimaryUat(tx *sqlx.Tx, pubkey *Pubkey, r *UserAttribute) error {
	if pubkey.PrimaryUat.String == r.ScopedDigest {
		if _, err := tx.Execv(`
UPDATE openpgp_pubkey SET primary_uat = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (l *Loader) insertSig(tx *sqlx.Tx, pubkey *Pubkey, r *Signature) error {
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

func (l *Loader) insertSigRelations(
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
		WHERE subkey_uuid = $3 AND sig_uuid = $4)`,
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
		WHERE uid_uuid = $3 AND sig_uuid = $4)`,
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
		WHERE uat_uuid = $3 AND sig_uuid = $4)`,
			sigRelationUuid, pubkey.RFingerprint, signed.ScopedDigest,
			r.ScopedDigest)
		if err != nil {
			return err
		}
	}
	return nil
}
