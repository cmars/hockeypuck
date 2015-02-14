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

// Revoked returns whether the target certification has been revoked, and the
// earliest time of revocation if there are multiple revocation signatures on
// that target. An error is returned if revocation signatures are present but
// cannot be checked.
func (s *SelfSigs) Revoked() (bool, time.Time, error) {
	panic("TODO")
}

// Valid returns whether the certification is valid. Valid certification means
// that the target has a non-expired, verified self-signature with no
// revocations. An error is returned if one or more signatures are not supported.
func (s *SelfSigs) Valid() (bool, error) {
	panic("TODO")
}

// Expired returns if the self-certifications will expire, and the latest
// expiration timestamp of all valid self-certifications. An error is returned
// if one or more signatures are not supported.
func (s *SelfSigs) Expired() (bool, time.Time, error) {
	panic("TODO")
}

// Primary returns whether the target is flagged as a primary identifier, the
// latest time at which the primary designation was made. An error is returned
// if one or more signatures are not supported.
func (s *SelfSigs) Primary() (bool, time.Time, error) {
	panic("TODO")
}
