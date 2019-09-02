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
	"crypto/md5"
	"encoding/hex"

	"gopkg.in/errgo.v1"
)

func SelfSignedOnly(key *PrimaryKey) error {
	var userIDs []*UserID
	var userAttributes []*UserAttribute
	var subKeys []*SubKey
	for _, uid := range key.UserIDs {
		ss := uid.SelfSigs(key)
		var certs []*Signature
		for _, cert := range ss.Certifications {
			if cert.Error == nil {
				certs = append(certs, cert.Signature)
			}
		}
		if len(certs) > 0 {
			uid.Signatures = certs
			userIDs = append(userIDs, uid)
		}
	}
	for _, uat := range key.UserAttributes {
		ss := uat.SelfSigs(key)
		var certs []*Signature
		for _, cert := range ss.Certifications {
			if cert.Error == nil {
				certs = append(certs, cert.Signature)
			}
		}
		if len(certs) > 0 {
			uat.Signatures = certs
			userAttributes = append(userAttributes, uat)
		}
	}
	for _, subKey := range key.SubKeys {
		ss := subKey.SelfSigs(key)
		var certs []*Signature
		for _, cert := range ss.Revocations {
			if cert.Error == nil {
				certs = append(certs, cert.Signature)
			}
		}
		for _, cert := range ss.Certifications {
			if cert.Error == nil {
				certs = append(certs, cert.Signature)
			}
		}
		if len(certs) > 0 {
			subKey.Signatures = certs
			subKeys = append(subKeys, subKey)
		}
	}
	key.UserIDs = userIDs
	key.UserAttributes = userAttributes
	key.SubKeys = subKeys
	return key.updateMD5()
}

func DropDuplicates(key *PrimaryKey) error {
	err := dedup(key, nil)
	if err != nil {
		return err
	}
	return key.updateMD5()
}

func CollectDuplicates(key *PrimaryKey) error {
	err := dedup(key, func(primary, _ packetNode) {
		primary.packet().Count++
	})
	if err != nil {
		return err
	}
	return key.updateMD5()
}

func Merge(dst, src *PrimaryKey) error {
	dst.UserIDs = append(dst.UserIDs, src.UserIDs...)
	dst.UserAttributes = append(dst.UserAttributes, src.UserAttributes...)
	dst.SubKeys = append(dst.SubKeys, src.SubKeys...)
	dst.Others = append(dst.Others, src.Others...)
	err := dedup(dst, func(primary, duplicate packetNode) {
		primaryPacket := primary.packet()
		duplicatePacket := duplicate.packet()
		if duplicatePacket.Count > primaryPacket.Count {
			primaryPacket.Count = duplicatePacket.Count
		}
	})
	if err != nil {
		return err
	}
	return dst.updateMD5()
}

func hexmd5(b []byte) string {
	d := md5.Sum(b)
	return hex.EncodeToString(d[:])
}

func dedup(root packetNode, handleDuplicate func(primary, duplicate packetNode)) error {
	nodes := map[string]packetNode{}

	for _, node := range root.contents() {
		uuid := node.uuid() + "_" + hexmd5(node.packet().Packet)
		primary, ok := nodes[uuid]
		if ok {
			err := primary.removeDuplicate(root, node)
			if err != nil {
				return errgo.Mask(err)
			}

			err = dedup(primary, nil)
			if err != nil {
				return errgo.Mask(err)
			}

			if handleDuplicate != nil {
				handleDuplicate(primary, node)
			}
		} else {
			nodes[uuid] = node
		}
	}
	return nil
}
