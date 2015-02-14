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
	"sort"
	"strings"
)

type uidSorter struct {
	*Pubkey
}

func (s *uidSorter) Len() int { return len(s.UserIDs) }

func (s *uidSorter) Less(i, j int) bool {
	iSig := maxSelfSig(s.Pubkey, s.UserIDs[i].Signatures)
	jSig := maxSelfSig(s.Pubkey, s.UserIDs[j].Signatures)
	return sigLess(iSig, jSig)
}

func sigLess(iSig *Signature, jSig *Signature) bool {
	if iSig != nil && jSig != nil {
		if iSig.Primary != jSig.Primary {
			return iSig.Primary
		}
		return iSig.Creation.Unix() > jSig.Creation.Unix()
	}
	return iSig != nil
}

func maxSelfSig(pubkey *Pubkey, sigs []*Signature) *Signature {
	var recent *Signature
	for _, sig := range sigs {
		if strings.HasPrefix(pubkey.UUID, sig.RIssuerKeyID) && (recent == nil || sig.Creation.Unix() > recent.Creation.Unix()) {
			recent = sig
		}
	}
	return recent
}

func (s *uidSorter) Swap(i, j int) {
	s.UserIDs[i], s.UserIDs[j] = s.UserIDs[j], s.UserIDs[i]
}

type uatSorter struct {
	*Pubkey
}

func (s *uatSorter) Len() int { return len(s.UserAttributes) }

func (s *uatSorter) Less(i, j int) bool {
	iSig := maxSelfSig(s.Pubkey, s.UserAttributes[i].Signatures)
	jSig := maxSelfSig(s.Pubkey, s.UserAttributes[j].Signatures)
	return sigLess(iSig, jSig)
}

func (s *uatSorter) Swap(i, j int) {
	s.UserAttributes[i], s.UserAttributes[j] = s.UserAttributes[j], s.UserAttributes[i]
}

type subkeySorter struct {
	*Pubkey
}

func (s *subkeySorter) Len() int { return len(s.Subkeys) }

func (s *subkeySorter) Less(i, j int) bool {
	return s.Subkeys[i].Creation.Unix() < s.Subkeys[j].Creation.Unix()
}

func (s *subkeySorter) Swap(i, j int) {
	s.Subkeys[i], s.Subkeys[j] = s.Subkeys[j], s.Subkeys[i]
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
	for _, node := range pubkey.contents() {
		switch p := node.(type) {
		case *Pubkey:
			sort.Sort(&sigSorter{p.Signatures})
			sort.Sort(&uidSorter{p})
			sort.Sort(&uatSorter{p})
			sort.Sort(&subkeySorter{p})
		case *Subkey:
			sort.Sort(&sigSorter{p.Signatures})
		case *UserID:
			sort.Sort(&sigSorter{p.Signatures})
		case *UserAttribute:
			sort.Sort(&sigSorter{p.Signatures})
		}
	}
}
