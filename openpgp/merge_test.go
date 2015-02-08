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
	gc "gopkg.in/check.v1"
)

type MergeSuite struct{}

var _ = gc.Suite(&MergeSuite{})

func (s *MergeSuite) TestMergeAddSig(c *gc.C) {
	unsignedKeys := MustInputAscKeys(c, "alice_unsigned.asc")
	c.Assert(unsignedKeys, gc.HasLen, 1)
	signedKeys := MustInputAscKeys(c, "alice_signed.asc")
	c.Assert(signedKeys, gc.HasLen, 1)

	hasExpectedSig := func(key *Pubkey) bool {
		for _, node := range key.contents() {
			sig, ok := node.(*Signature)
			if ok && sig.RIssuerKeyID == "62aea01d67640fb5" {
				return true
			}
		}
		return false
	}
	c.Assert(hasExpectedSig(unsignedKeys[0]), gc.Equals, false)
	c.Assert(hasExpectedSig(signedKeys[0]), gc.Equals, true)
	Merge(unsignedKeys[0], signedKeys[0])
	c.Assert(hasExpectedSig(unsignedKeys[0]), gc.Equals, true)
}
