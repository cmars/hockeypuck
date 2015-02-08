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
	"gopkg.in/errgo.v1"
)

func Deduplicate(root packetNode) error {
	return dedup(root, func(primary, _ packetNode) {
		primary.packet().Count++
	})
}

func dedup(root packetNode, handleDuplicate func(primary, duplicate packetNode)) error {
	nodes := map[string]packetNode{}

	var parent packetNode
	for _, node := range root.contents() {
		primary, ok := nodes[node.uuid()]
		if ok {
			if parent == nil {
				return errgo.Newf("cannot determine parent of node: %+v", node)
			}
			err := primary.removeDuplicate(parent, node)
			if err != nil {
				return errgo.Mask(err)
			}

			if handleDuplicate != nil {
				handleDuplicate(primary, node)
			}

			err = dedup(primary, handleDuplicate)
			if err != nil {
				return errgo.Mask(err)
			}
		} else {
			nodes[node.uuid()] = node
		}

		switch p := node.(type) {
		case *Pubkey:
			parent = p
		case *Subkey:
			parent = p
		case *UserID:
			parent = p
		case *UserAttribute:
			parent = p
		}
	}
	return nil
}

func Merge(dst, src *Pubkey) error {
	dst.UserIDs = append(dst.UserIDs, src.UserIDs...)
	dst.UserAttributes = append(dst.UserAttributes, src.UserAttributes...)
	dst.Subkeys = append(dst.Subkeys, src.Subkeys...)
	dst.Others = append(dst.Others, src.Others...)
	return dedup(dst, func(primary, duplicate packetNode) {
		primaryPacket := primary.packet()
		duplicatePacket := duplicate.packet()
		if duplicatePacket.Count > primaryPacket.Count {
			primaryPacket.Count = duplicatePacket.Count
		}
	})
}

/*
// Resolve resolves and connects relationship references
// between the different packet records in the key material.
func Resolve(pubkey *Pubkey) {
	var signable Signable
	scopedPackets := make(map[string]bool)
	pubkey.Visit(func(rec PacketRecord) error {
		switch p := rec.(type) {
		case *Pubkey:
			r.setSigScope(p.RFingerprint, p.signatures...)
			p.linkSelfSigs()
			signable = p
		case *UserId:
			p.ScopedDigest = p.calcScopedDigest(r.Pubkey)
			if _, has := scopedPackets[p.ScopedDigest]; has {
				r.Pubkey.userIds = removeUserId(r.Pubkey.userIds, p)
				r.Pubkey.Unsupported = append(r.Pubkey.Unsupported, p.Packet...)
				r.Pubkey.Unsupported = append(r.Pubkey.Unsupported, concatSigPackets(p.signatures)...)
				p.signatures = nil
			} else {
				scopedPackets[p.ScopedDigest] = true
				r.setSigScope(p.ScopedDigest, p.signatures...)
				p.linkSelfSigs(r.Pubkey)
				signable = p
				// linkSelfSigs needs to set creation & expiration
			}
		case *UserAttribute:
			p.ScopedDigest = p.calcScopedDigest(r.Pubkey)
			if _, has := scopedPackets[p.ScopedDigest]; has {
				r.Pubkey.userAttributes = removeUserAttribute(r.Pubkey.userAttributes, p)
				r.Pubkey.Unsupported = append(r.Pubkey.Unsupported, p.Packet...)
				r.Pubkey.Unsupported = append(r.Pubkey.Unsupported, concatSigPackets(p.signatures)...)
				p.signatures = nil
			} else {
				scopedPackets[p.ScopedDigest] = true
				r.setSigScope(p.ScopedDigest, p.signatures...)
				p.linkSelfSigs(r.Pubkey)
				signable = p
				// linkSelfSigs needs to set creation & expiration
			}
		case *Subkey:
			if _, has := scopedPackets[p.RFingerprint]; has {
				r.Pubkey.subkeys = removeSubkey(r.Pubkey.subkeys, p)
				r.Pubkey.Unsupported = append(r.Pubkey.Unsupported, p.Packet...)
				r.Pubkey.Unsupported = append(r.Pubkey.Unsupported, concatSigPackets(p.signatures)...)
				p.signatures = nil
			} else {
				scopedPackets[p.RFingerprint] = true
				r.setSigScope(p.RFingerprint, p.signatures...)
				p.linkSelfSigs(r.Pubkey)
				signable = p
			}
		case *Signature:
			if _, has := scopedPackets[p.ScopedDigest]; has {
				signable.RemoveSignature(p)
				r.Pubkey.Unsupported = append(r.Pubkey.Unsupported, p.Packet...)
			} else {
				scopedPackets[p.ScopedDigest] = true
			}
		}
		return nil
	})
	Sort(pubkey)
	// Designate first UID / UAT as primary
	if len(pubkey.userIds) > 0 {
		pubkey.primaryUid = pubkey.userIds[0]
		pubkey.primaryUidSig = pubkey.primaryUid.selfSignature
		pubkey.PrimaryUid = sql.NullString{pubkey.primaryUid.ScopedDigest, true}
	} else {
		pubkey.primaryUid = nil
		pubkey.primaryUidSig = nil
		pubkey.PrimaryUid = sql.NullString{"", false}
	}
	if len(pubkey.userAttributes) > 0 {
		pubkey.primaryUat = pubkey.userAttributes[0]
		pubkey.primaryUatSig = pubkey.primaryUat.selfSignature
		pubkey.PrimaryUat = sql.NullString{pubkey.primaryUat.ScopedDigest, true}
	} else {
		pubkey.primaryUat = nil
		pubkey.primaryUatSig = nil
		pubkey.PrimaryUat = sql.NullString{"", false}
	}
}

func (r *resolver) setSigScope(scope string, sigs ...*Signature) {
	for _, sig := range sigs {
		sig.ScopedDigest = sig.calcScopedDigest(r.Pubkey, scope)
	}
}

func removeUserId(uids []*UserId, removeUid *UserId) (result []*UserId) {
	for _, uid := range uids {
		if removeUid != uid {
			result = append(result, uid)
		}
	}
	return
}

func removeUserAttribute(uats []*UserAttribute, removeUat *UserAttribute) (result []*UserAttribute) {
	for _, uat := range uats {
		if removeUat != uat {
			result = append(result, uat)
		}
	}
	return
}

func removeSubkey(subkeys []*Subkey, removeSubkey *Subkey) (result []*Subkey) {
	for _, subkey := range subkeys {
		if removeSubkey != subkey {
			result = append(result, subkey)
		}
	}
	return
}

func removeSignature(sigs []*Signature, removeSig *Signature) (result []*Signature) {
	for _, sig := range sigs {
		if removeSig != sig {
			result = append(result, sig)
		}
	}
	return
}

func concatSigPackets(sigs []*Signature) []byte {
	var result []byte
	for _, sig := range sigs {
		result = append(result, sig.Packet...)
	}
	return result
}
*/
