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
	"sort"
)

type uidSorter struct {
	userIds []*UserId
}

func (s *uidSorter) Len() int { return len(s.userIds) }

func (s *uidSorter) Less(i, j int) bool {
	iPrimary := hasPrimarySignature(s.userIds[i].signatures)
	jPrimary := hasPrimarySignature(s.userIds[j].signatures)
	if iPrimary != jPrimary {
		// if one uid has a primary sig and the other doesn't,
		// the one with the primary comes first.
		return iPrimary
	}
	return s.userIds[i].selfSignature.Creation.Unix() > s.userIds[j].selfSignature.Creation.Unix()
}

func hasPrimarySignature(sigs []*Signature) bool {
	for _, sig := range sigs {
		if sig.IsPrimary() {
			return true
		}
	}
	return false
}

func (s *uidSorter) Swap(i, j int) {
	s.userIds[i], s.userIds[j] = s.userIds[j], s.userIds[i]
}

type uatSorter struct {
	userAttributes []*UserAttribute
}

func (s *uatSorter) Len() int { return len(s.userAttributes) }

func (s *uatSorter) Less(i, j int) bool {
	iPrimary := hasPrimarySignature(s.userAttributes[i].signatures)
	jPrimary := hasPrimarySignature(s.userAttributes[j].signatures)
	if iPrimary != jPrimary {
		// if one uid has a primary sig and the other doesn't,
		// the one with the primary comes first.
		return iPrimary
	}
	return s.userAttributes[i].selfSignature.Creation.Unix() > s.userAttributes[j].selfSignature.Creation.Unix()
}

func (s *uatSorter) Swap(i, j int) {
	s.userAttributes[i], s.userAttributes[j] = s.userAttributes[j], s.userAttributes[i]
}

type subkeySorter struct {
	subkeys []*Subkey
}

func (s *subkeySorter) Len() int { return len(s.subkeys) }

func (s *subkeySorter) Less(i, j int) bool {
	if (s.subkeys[i].revSig == nil) != (s.subkeys[j].revSig == nil) {
		return s.subkeys[i].revSig != nil
	}
	return s.subkeys[i].Creation.Unix() < s.subkeys[j].Creation.Unix()
}

func (s *subkeySorter) Swap(i, j int) {
	s.subkeys[i], s.subkeys[j] = s.subkeys[j], s.subkeys[i]
}

type sigSorter struct {
	sigs []*Signature
}

func (s *sigSorter) Len() int { return len(s.sigs) }

func (s *sigSorter) Less(i, j int) bool {
	return s.sigs[i].Creation.Unix() < s.sigs[j].Creation.Unix()
}

func (s *sigSorter) Swap(i, j int) {
	s.sigs[i], s.sigs[j] = s.sigs[j], s.sigs[i]
}

// Sort reorders the key material
func Sort(pubkey *Pubkey) {
	pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *UserId:
			sort.Sort(&sigSorter{r.signatures})
		case *UserAttribute:
			sort.Sort(&sigSorter{r.signatures})
		case *Subkey:
			sort.Sort(&sigSorter{r.signatures})
		}
		return nil
	})
	sort.Sort(&uidSorter{pubkey.userIds})
	sort.Sort(&uatSorter{pubkey.userAttributes})
	sort.Sort(&subkeySorter{pubkey.subkeys})
}
