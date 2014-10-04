/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

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
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/hockeypuck/hockeypuck/util"
)

type Loader struct {
	db   *DB
	bulk bool
}

func NewLoader(db *DB, bulk bool) *Loader {
	return &Loader{db: db, bulk: bulk}
}

func (l *Loader) Begin() (*sqlx.Tx, error) {
	return l.db.Beginx()
}

func (l *Loader) Commit(tx *sqlx.Tx) error {
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (l *Loader) Rollback(tx *sqlx.Tx) error {
	return tx.Rollback()
}

func (l *Loader) InsertKey(pubkey *Pubkey) error {
	tx, err := l.Begin()
	if err != nil {
		return err
	}
	err = l.InsertKeyTx(tx, pubkey)
	if err != nil {
		tx.Rollback()
	} else {
		return tx.Commit()
	}
	return err
}

func (l *Loader) InsertKeyTx(tx *sqlx.Tx, pubkey *Pubkey) error {
	var signable PacketRecord
	err := pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			if err := l.insertPubkey(tx, r); err != nil {
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
			signable = r
		case *UserAttribute:
			if err := l.insertUat(tx, pubkey, r); err != nil {
				return err
			}
			signable = r
		case *Signature:
			if err := l.insertSig(tx, pubkey, signable, r); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// insertSelectFrom completes an INSERT INTO .. SELECT FROM
// SQL statement based on the loader's bulk loading mode.
func (l *Loader) insertSelectFrom(sql, table, where string) string {
	if !l.bulk {
		sql = fmt.Sprintf("%s WHERE NOT EXISTS (SELECT 1 FROM %s WHERE %s)",
			sql, table, where)
	}
	return sql
}

func (l *Loader) insertPubkey(tx *sqlx.Tx, r *Pubkey) error {
	_, err := Execv(tx, l.insertSelectFrom(`
INSERT INTO openpgp_pubkey (
	uuid, creation, expiration, state, packet,
	ctime, mtime,
    md5, sha256, revsig_uuid, primary_uid, primary_uat,
	algorithm, bit_len, unsupp)
SELECT $1, $2, $3, $4, $5,
	now(), now(),
    $6, $7, $8, $9, $10,
	$11, $12, $13`,
		"openpgp_pubkey", "uuid = $1"),
		r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
		// TODO: use mtime and ctime from record, or use RETURNING to set it
		r.Md5, r.Sha256, r.RevSigDigest, r.PrimaryUid, r.PrimaryUat,
		r.Algorithm, r.BitLen, r.Unsupported)
	return err
}

func (l *Loader) insertSubkey(tx *sqlx.Tx, pubkey *Pubkey, r *Subkey) error {
	_, err := Execv(tx, l.insertSelectFrom(`
INSERT INTO openpgp_subkey (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid, algorithm, bit_len)
SELECT $1, $2, $3, $4, $5,
	$6, $7, $8, $9`,
		"openpgp_subkey", "uuid = $1"),
		r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.RevSigDigest, r.Algorithm, r.BitLen)
	return err
}

func (l *Loader) insertUid(tx *sqlx.Tx, pubkey *Pubkey, r *UserId) error {
	_, err := Execv(tx, l.insertSelectFrom(`
INSERT INTO openpgp_uid (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid, keywords, keywords_fulltext)
SELECT $1, $2, $3, $4, $5,
	$6, $7, $8, to_tsvector($8)`,
		"openpgp_uid", "uuid = $1"),
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.RevSigDigest, util.CleanUtf8(r.Keywords))
	return err
}

func (l *Loader) insertUat(tx *sqlx.Tx, pubkey *Pubkey, r *UserAttribute) error {
	_, err := Execv(tx, l.insertSelectFrom(`
INSERT INTO openpgp_uat (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid)
SELECT $1, $2, $3, $4, $5,
	$6, $7`,
		"openpgp_uat", "uuid = $1"),
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.RevSigDigest)
	return err
}

func (l *Loader) insertSig(tx *sqlx.Tx, pubkey *Pubkey, signable PacketRecord, r *Signature) error {
	baseSql := `
INSERT INTO openpgp_sig (
	uuid, creation, expiration, state, packet,
	sig_type, signer, signer_uuid%s)
SELECT $1, $2, $3, $4, $5, $6, $7, $8%s`
	matchSql := "uuid = $1"
	args := []interface{}{
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		r.SigType, r.RIssuerKeyId, r.RIssuerFingerprint,
	}
	var sql string
	switch signed := signable.(type) {
	case *Pubkey:
		sql = fmt.Sprintf(baseSql,
			", pubkey_uuid",
			", $9")
		args = append(args, signed.RFingerprint)
		matchSql += " AND pubkey_uuid = $9"
	case *Subkey:
		sql = fmt.Sprintf(baseSql,
			", pubkey_uuid, subkey_uuid",
			", $9, $10")
		args = append(args, pubkey.RFingerprint, signed.RFingerprint)
		matchSql += " AND pubkey_uuid = $9 AND subkey_uuid = $10"
	case *UserId:
		sql = fmt.Sprintf(baseSql,
			", pubkey_uuid, uid_uuid",
			", $9, $10")
		args = append(args, pubkey.RFingerprint, signed.ScopedDigest)
		matchSql += " AND pubkey_uuid = $9 AND uid_uuid = $10"
	case *UserAttribute:
		sql = fmt.Sprintf(baseSql,
			", pubkey_uuid, uat_uuid",
			", $9, $10")
		args = append(args, pubkey.RFingerprint, signed.ScopedDigest)
		matchSql += " AND pubkey_uuid = $9 AND uat_uuid = $10"
	case *Signature:
		sql = fmt.Sprintf(baseSql,
			", pubkey_uuid, sig_uuid",
			", $9, $10")
		args = append(args, pubkey.RFingerprint, signed.ScopedDigest)
		matchSql += " AND pubkey_uuid = $9 AND sig_uuid = $10"
	default:
		return fmt.Errorf("Unsupported packet record type: %v", signed)
	}
	_, err := Execv(tx, l.insertSelectFrom(sql, "openpgp_sig", matchSql), args...)
	// TODO: use RETURNING to update matched issuer fingerprint
	return err
}
