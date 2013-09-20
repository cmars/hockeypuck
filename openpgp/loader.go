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
	tx *sqlx.Tx
}

func NewLoader(db *DB) *Loader {
	return &Loader{db: db}
}

func (l *Loader) Begin() (_ *sqlx.Tx, err error) {
	l.tx, err = l.db.Beginx()
	return l.tx, err
}

func (l *Loader) Commit() (err error) {
	if err = l.tx.Commit(); err != nil {
		return
	}
	return
}

func (l *Loader) Rollback() (err error) {
	err = l.tx.Rollback()
	return
}

func (l *Loader) InsertKey(pubkey *Pubkey) (err error) {
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			if err := l.insertPubkey(r); err != nil {
				return err
			}
			signable = r
		case *Subkey:
			if err := l.insertSubkey(pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserId:
			if err := l.insertUid(pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserAttribute:
			if err := l.insertUat(pubkey, r); err != nil {
				return err
			}
			signable = r
		case *Signature:
			if err := l.insertSig(pubkey, r); err != nil {
				return err
			}
			if err := l.insertSigRelations(pubkey, signable, r); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (l *Loader) insertPubkey(r *Pubkey) error {
	_, err := l.tx.Execv(`
INSERT INTO openpgp_pubkey (
	uuid, creation, expiration, state, packet,
	ctime, mtime,
    md5, sha256, revsig_uuid, primary_uid, primary_uat,
	algorithm, bit_len, unsupp)
VALUES (
	$1, $2, $3, $4, $5,
	now(), now(),
    $6, $7, $8, $9, $10,
	$11, $12, $13)`,
		r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
		// TODO: use mtime and ctime from record, or use RETURNING to set it
		r.Md5, r.Sha256, r.RevSigDigest, r.PrimaryUid, r.PrimaryUat,
		r.Algorithm, r.BitLen, r.Unsupported)
	return err
}

func (l *Loader) insertSubkey(pubkey *Pubkey, r *Subkey) error {
	_, err := l.tx.Execv(`
INSERT INTO openpgp_subkey (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid, algorithm, bit_len)
VALUES (
	$1, $2, $3, $4, $5,
	$6, $7, $8, $9)`,
		r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.RevSigDigest, r.Algorithm, r.BitLen)
	return err
}

func (l *Loader) insertUid(pubkey *Pubkey, r *UserId) error {
	_, err := l.tx.Execv(`
INSERT INTO openpgp_uid (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid, keywords, keywords_fulltext)
VALUES (
	$1, $2, $3, $4, $5,
	$6, $7, $8, to_tsvector($8))`,
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.RevSigDigest, r.Keywords)
	return err
}

func (l *Loader) insertUat(pubkey *Pubkey, r *UserAttribute) error {
	_, err := l.tx.Execv(`
INSERT INTO openpgp_uat (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid)
VALUES (
	$1, $2, $3, $4, $5,
	$6, $7)`,
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.RevSigDigest)
	return err
}

func (l *Loader) insertSig(pubkey *Pubkey, r *Signature) error {
	_, err := l.tx.Execv(`
INSERT INTO openpgp_sig (
	uuid, creation, expiration, state, packet,
	sig_type, signer, signer_uuid)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		r.SigType, r.RIssuerKeyId, r.RIssuerFingerprint)
	// TODO: use RETURNING to update matched issuer fingerprint
	return err
}

func (l *Loader) insertSigRelations(pubkey *Pubkey, signable PacketRecord, r *Signature) error {
	sigRelationUuid, err := NewUuid()
	if err != nil {
		return err
	}
	// Add signature relation to other packets
	switch signed := signable.(type) {
	case *Pubkey:
		_, err = l.tx.Execv(`
INSERT INTO openpgp_pubkey_sig (uuid, pubkey_uuid, sig_uuid)
VALUES ($1, $2, $3)`, sigRelationUuid, signed.RFingerprint, r.ScopedDigest)
		if err != nil {
			return err
		}
	case *Subkey:
		_, err = l.tx.Execv(`
INSERT INTO openpgp_subkey_sig (uuid, pubkey_uuid, subkey_uuid, sig_uuid)
VALUES ($1, $2, $3, $4)`, sigRelationUuid, pubkey.RFingerprint,
			signed.RFingerprint, r.ScopedDigest)
		if err != nil {
			return err
		}
	case *UserId:
		_, err = l.tx.Execv(`
INSERT INTO openpgp_uid_sig (uuid, pubkey_uuid, uid_uuid, sig_uuid)
VALUES ($1, $2, $3, $4)`, sigRelationUuid, pubkey.RFingerprint,
			signed.ScopedDigest, r.ScopedDigest)
		if err != nil {
			return err
		}
	case *UserAttribute:
		_, err = l.tx.Execv(`
INSERT INTO openpgp_uat_sig (uuid, pubkey_uuid, uat_uuid, sig_uuid)
VALUES ($1, $2, $3, $4)`, sigRelationUuid, pubkey.RFingerprint,
			signed.ScopedDigest, r.ScopedDigest)
		if err != nil {
			return err
		}
	}
	return nil
}
