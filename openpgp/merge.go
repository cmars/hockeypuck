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
	"errors"
)

type PacketRecordMap map[string]PacketRecord

var ErrMissingUuid error = errors.New("Packet record missing content-unique identifier")

func GetUuid(rec PacketRecord) string {
	switch r := rec.(type) {
	case *Pubkey:
		return r.RFingerprint
	case *Signature:
		return r.ScopedDigest
	case *UserId:
		return r.ScopedDigest
	case *UserAttribute:
		return r.ScopedDigest
	case *Subkey:
		return r.RFingerprint
	}
	return ""
}

func (m PacketRecordMap) visit(rec PacketRecord) error {
	uuid := GetUuid(rec)
	if uuid == "" {
		return ErrMissingUuid
	} else if _, ok := m[uuid]; !ok {
		m[uuid] = rec
	}
	return nil
}

// Map a tree of packet objects by strong hash.
func MapKey(pubkey *Pubkey) PacketRecordMap {
	m := make(PacketRecordMap)
	m.visit(pubkey)
	return m
}

// Merge the contents of srcKey into dstKey, modifying in-place.
// Packets in src not found in dst are appended to the matching parent.
// Conflicting packets and unmatched parents are ignored.
func MergeKey(dstKey *Pubkey, srcKey *Pubkey) {
	dstObjects := MapKey(dstKey)
	// Track source signable object in source traversal
	var srcSignable PacketRecord
	srcKey.Visit(func(srcObj PacketRecord) error {
		// Match in destination tree
		_, dstHas := dstObjects[GetUuid(srcObj)]
		if dstHas {
			return nil // We already have it
		}
		switch so := srcObj.(type) {
		case *Pubkey:
			srcSignable = so
		case *Subkey:
			srcSignable = so
			if !dstHas {
				dstKey.subkeys = append(dstKey.subkeys, so)
			}
		case *UserId:
			srcSignable = so
			if !dstHas {
				dstKey.userIds = append(dstKey.userIds, so)
			}
		case *UserAttribute:
			srcSignable = so
			if !dstHas {
				dstKey.userAttributes = append(dstKey.userAttributes, so)
			}
		case *Signature:
			dstParent, dstHasParent := dstObjects[GetUuid(srcSignable)]
			dstSignable, isSignable := dstParent.(Signable)
			if !dstHas && dstHasParent && isSignable {
				dstSignable.AddSignature(so)
			}
		}
		return nil
	})
}
