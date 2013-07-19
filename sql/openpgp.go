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

package mgo

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp/armor"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	. "launchpad.net/hockeypuck"
	"log"
	"regexp"
	"strings"
	"time"
	"unicode"
)

type OpenpgpDb interface {
	// CreateTables creates the relational database tables if they do not already exist.
	// The implementation must be idempotent enough to skip tables that already exist.
	// Automatic schema migration is not expected.
	CreateTables() error
	// CreateIndexes creates the relational database indexes if they do not already exist.
	// The implementation must be idempotent enough to skip tables that already exist.
	// Automatic schema migration is not expected.
	CreateIndexes() error
	// LookupKeys finds keys matching a free-form search string, as defined in the HKP draft
	// specification. Strings prefixed with 0x are treated as a key ID, all others are a full-text
	// search on the User ID keytext.
	LookupKeys(search string, limit int) ([]*PubKey, error)
	// LookupShortId finds a key matching the given 4-byte public key fingerprint suffix, in hex.
	LookupShortId(shortId string) (*PubKey, error)
	// LookupKeyId finds a key matching the given 8-byte public key fingerprint suffix, in hex.
	LookupLongId(longId string) (*PubKey, error)
	// LookupFingerprint finds a key matching the full 20-byte public key fingerprint suffix, in hex.
	LookupFingerprint(fp string) (*PubKey, error)
	// UpsertKey will insert a new public key, or update an existing key that matches the fingerprint.
	UpsertKey(pubkey *PubKey) (*LoadKeyStatus, error)
	// UpdateStats will update the keyserver database statistics displayed for op=stats.
	UpdateStats() error
	// Stats provides the information used to report an op=stats request.
	Stats() (stats *ServerStats, err error)
}

func LookupKeyId(db OpenpgpDb, keyId string) (*PubKey, error) {
	keyId = strings.ToLower(keyId)
	raw, err := hex.DecodeString(keyId)
	if err != nil {
		return nil, InvalidKeyId
	}
	switch len(raw) {
	case 4:
		return db.LookupShortId(keyId)
	case 8:
		return db.LookupLongId(keyId)
	case 20:
		return db.LookupFingerprint(keyId)
	default:
		return nil, InvalidKeyId
	}
	panic("unreachable")
}
