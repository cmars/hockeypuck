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

package hockeypuck

import (
	"bytes"
	"errors"
	"bitbucket.org/cmars/go.crypto/openpgp"
	"bitbucket.org/cmars/go.crypto/openpgp/packet"
)

// Merge entity from src into dst, adding additional identities,
// signatures, and subkeys in src not already in dst.
// The keyring dst is modified in-place.
func MergeEntity(dst *openpgp.Entity, src *openpgp.Entity) (err error) {
	if dst.PrimaryKey.Fingerprint != src.PrimaryKey.Fingerprint {
		err = errors.New("Merge failed, primary key fingerprints do not match.")
		return
	}
	for _, srcIdent := range src.Identities {
		dstIdent, has := dst.Identities[srcIdent.Name]
		if !has {
			dst.Identities[srcIdent.Name] = dstIdent
		} else {
			srcSigs := mapSigs(srcIdent.Signatures)
			dstSigs := mapSigs(dstIdent.Signatures)
			for srcRaw, srcSig := range srcSigs {
				_, has := dstSigs[srcRaw]
				if !has {
					dstIdent.Signatures = append(dstIdent.Signatures, srcSig)
				}
			}
		}
	}
	srcSubkeys := mapSubkeys(src)
	dstSubkeys := mapSubkeys(dst)
	for srcSkFp, srcSubkey := range srcSubkeys {
		_, has := dstSubkeys[srcSkFp]
		if !has {
			dst.Subkeys = append(dst.Subkeys, *srcSubkey)
		}
	}
	return
}

func mapSigs(sigs []*packet.Signature) map[string]*packet.Signature {
	result := make(map[string]*packet.Signature)
	for _, sig := range sigs {
		raw := bytes.NewBuffer([]byte{})
		sig.Serialize(raw)
		result[raw.String()] = sig
	}
	return result
}

func mapSubkeys(e *openpgp.Entity) map[[20]byte]*openpgp.Subkey {
	result := make(map[[20]byte]*openpgp.Subkey)
	for _, subkey := range e.Subkeys {
		result[subkey.PublicKey.Fingerprint] = &subkey
	}
	return result
}
