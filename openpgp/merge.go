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
	// Track src parent object in src traverse
	var srcPubkey *Pubkey
	var srcUserId *UserId
	var srcSignable PacketRecord
	var srcParent PacketRecord
	var hasParent bool
	srcKey.Visit(func(srcObj PacketRecord) error {
		switch srcObj.(type) {
		case *Pubkey:
			srcPubkey = srcObj.(*Pubkey)
			srcSignable = srcObj
			srcParent = nil
			hasParent = false
		case *UserId:
			srcUserId = srcObj.(*UserId)
			srcSignable = srcObj
			srcParent = srcPubkey
			hasParent = true
		case *UserAttribute:
			srcSignable = srcObj
			srcParent = srcUserId
			hasParent = true
		case *Subkey:
			srcSignable = srcObj
			srcParent = srcPubkey
			hasParent = true
		case *Signature:
			srcParent = srcSignable
			hasParent = true
		}
		// match in dst tree
		_, dstHas := dstObjects[GetUuid(srcObj)]
		if dstHas {
			return nil // We already have it
		}
		if hasParent {
			dstParentObj, dstHasParent := dstObjects[GetUuid(srcParent)]
			if dstHasParent {
				appendPacketRecord(dstParentObj, srcObj)
			}
		}
		return nil
	})
}

// Append a src packet under dst parent.
func appendPacketRecord(dstParent PacketRecord, srcObj PacketRecord) {
	if sig, isa := srcObj.(*Signature); isa {
		if dst, isa := dstParent.(Signable); isa {
			dst.AddSignature(sig)
		}
	} else if uid, isa := srcObj.(*UserId); isa {
		if pubkey, isa := dstParent.(*Pubkey); isa {
			pubkey.userIds = append(pubkey.userIds, uid)
		}
	} else if uattr, isa := srcObj.(*UserAttribute); isa {
		if pubkey, isa := dstParent.(*Pubkey); isa {
			pubkey.userAttributes = append(pubkey.userAttributes, uattr)
		}
	} else if subkey, isa := srcObj.(*Subkey); isa {
		if pubkey, isa := dstParent.(*Pubkey); isa {
			pubkey.subkeys = append(pubkey.subkeys, subkey)
		}
	}
}
