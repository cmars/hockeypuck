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

import "time"

type CheckSig struct {
	Pubkey    *Pubkey
	Signature *Signature
	Error     error

	target packetNode
}

// SelfSigs holds self-signatures on OpenPGP targets, which may be keys, user
// IDs, or user attributes.
type SelfSigs struct {
	Revocations    []*CheckSig
	Certifications []*CheckSig
}

// Revoked returns the earliest revocation of the target, and whether a
// valid revocation exists at all.
func (s *SelfSigs) Revoked() (time.Time, bool) {
	var t time.Time
	if len(s.Revocations) == 0 {
		return t, false
	}
	for _, cksig := range s.Revocations {
		if cksig.Error != nil {
			continue
		}
		if t.IsZero() || t.Unix() > cksig.Signature.Creation.Unix() {
			t = cksig.Signature.Creation
		}
	}
	return t, !t.IsZero()
}

// Valid returns the latest expiration, whether an expiration has been set,
// and whether a valid self-signature exists at all.
func (s *SelfSigs) Valid() (time.Time, bool, bool) {
	var t time.Time
	var ok bool
	if len(s.Certifications) == 0 {
		return t, false, false
	}
	for _, ckSig := range s.Certifications {
		if ckSig.Error != nil {
			continue
		}
		ok = true
		if !ckSig.Signature.Expiration.IsZero() {
			if t.IsZero() || t.Unix() < ckSig.Signature.Expiration.Unix() {
				t = ckSig.Signature.Expiration
			}
		}
	}
	return t, !t.IsZero(), ok
}

// Primary returns the latest time when the target was flagged as a primary
// identifier, and whether such a claim even exists on the target.
func (s *SelfSigs) Primary() (time.Time, bool) {
	var t time.Time
	if len(s.Certifications) == 0 {
		return t, false
	}
	for _, ckSig := range s.Certifications {
		if ckSig.Error != nil {
			continue
		}
		if ckSig.Signature.Primary {
			if t.IsZero() || t.Unix() < ckSig.Signature.Creation.Unix() {
				t = ckSig.Signature.Creation
			}
		}
	}
	return t, !t.IsZero()
}
