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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeAddSig(t *testing.T) {
	unsignedKeys := MustInputAscKeys(t, "alice_unsigned.asc")
	assert.Equal(t, 1, len(unsignedKeys))
	signedKeys := MustInputAscKeys(t, "alice_signed.asc")
	assert.Equal(t, 1, len(signedKeys))
	expectedSigCount := func(key *Pubkey) (count int) {
		key.Visit(func(rec PacketRecord) error {
			switch r := rec.(type) {
			case *Signature:
				if r.IssuerKeyId() == "62aea01d67640fb5" {
					count++
				}
			}
			return nil
		})
		return
	}
	assert.Equal(t, 0, expectedSigCount(unsignedKeys[0]))
	assert.Equal(t, 1, expectedSigCount(signedKeys[0]))
	MergeKey(unsignedKeys[0], signedKeys[0])
	assert.Equal(t, 1, expectedSigCount(unsignedKeys[0]))
}
