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

package hockeypuck

// Merge the contents of srcKey into dstKey, modifying in-place.
// Packets in src not found in dst are appended to the matching parent.
// Conflicting packets and unmatched parents are ignored.
func MergeKey(dstKey *PubKey, srcKey *PubKey) {
	dstObjects := mapKey(dstKey)
	pktObjChan := make(chan PacketObject)
	defer FinishTraversal(pktObjChan)
	go func() {
		srcKey.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	// Track src parent object in src traverse
	var srcPubKey *PubKey
	var srcUserId *UserId
	var srcSignable PacketObject
	var srcParent PacketObject
	var hasParent bool
	for srcObj := range pktObjChan {
		switch srcObj.(type) {
		case *PubKey:
			srcPubKey = srcObj.(*PubKey)
			srcSignable = srcObj
			srcParent = nil
			hasParent = false
		case *UserId:
			srcUserId = srcObj.(*UserId)
			srcSignable = srcObj
			srcParent = srcPubKey
			hasParent = true
		case *UserAttribute:
			srcSignable = srcObj
			srcParent = srcUserId
			hasParent = true
		case *SubKey:
			srcSignable = srcObj
			srcParent = srcPubKey
			hasParent = true
		case *Signature:
			srcParent = srcSignable
			hasParent = true
		}
		// match in dst tree
		_, dstHas := dstObjects[srcObj.GetDigest()]
		if dstHas {
			continue // We already have it
		}
		if hasParent {
			dstParentObj, dstHasParent := dstObjects[srcParent.GetDigest()]
			if dstHasParent {
				appendPacketObject(dstParentObj, srcObj)
			}
		}
	}
}

// Map a tree of packet objects by strong hash.
func mapKey(root PacketObject) (objects map[string]PacketObject) {
	objects = make(map[string]PacketObject)
	pktObjChan := make(chan PacketObject)
	defer FinishTraversal(pktObjChan)
	go func() {
		root.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	for pktObj := range pktObjChan {
		objects[pktObj.GetDigest()] = pktObj
	}
	return
}

// Append a src packet under dst parent.
func appendPacketObject(dstParent PacketObject, srcObj PacketObject) {
	if sig, isa := srcObj.(*Signature); isa {
		if dst, isa := dstParent.(Signable); isa {
			dst.AppendSig(sig)
		}
	} else if uattr, isa := srcObj.(*UserAttribute); isa {
		if uid, isa := dstParent.(*UserId); isa {
			uid.Attributes = append(uid.Attributes, uattr)
		}
	} else if uid, isa := srcObj.(*UserId); isa {
		if pubKey, isa := dstParent.(*PubKey); isa {
			pubKey.Identities = append(pubKey.Identities, uid)
		}
	} else if subKey, isa := srcObj.(*SubKey); isa {
		if pubKey, isa := dstParent.(*PubKey); isa {
			pubKey.SubKeys = append(pubKey.SubKeys, subKey)
		}
	}
}
