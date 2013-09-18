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
	//P "code.google.com/p/go.crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVisitor(t *testing.T) {
	key := MustInputAscKey(t, "sksdigest.asc")
	t.Log(key.userIds[0].signatures[0])
	var npub, nuid, nsub, nsig int
	key.Visit(func(rec PacketRecord) error {
		switch rec.(type) {
		case *Pubkey:
			npub++
		case *UserId:
			nuid++
		case *Subkey:
			nsub++
		case *Signature:
			nsig++
		}
		return nil
	})
	assert.Equal(t, 1, npub)
	assert.Equal(t, 1, nuid)
	assert.Equal(t, 1, nsub)
	assert.Equal(t, 2, nsig)
}

func TestIterOpaque(t *testing.T) {
	key := MustInputAscKey(t, "sksdigest.asc")
	hits := make(map[uint8]int)
	for _, tag := range []uint8{
		2, 6, 13, 14} {
		//P.PacketTypeSignature, P.PacketTypePublicKey,
		//P.PacketTypeUserId, P.PacketTypePublicSubkey} {
		hits[tag] = 0
	}
	err := key.Visit(func(rec PacketRecord) error {
		if opkt, err := rec.GetOpaquePacket(); err == nil {
			hits[opkt.Tag]++
		}
		return nil
	})
	assert.Nil(t, err)
	t.Log(hits)
	assert.Equal(t, 2, hits[2 /*P.PacketTypeSignature*/])
	assert.Equal(t, 1, hits[6 /*P.PacketTypePublicKey*/])
	assert.Equal(t, 1, hits[13 /*P.PacketTypeUserId*/])
	assert.Equal(t, 1, len(key.userIds))
	assert.Equal(t, 1, len(key.userIds[0].signatures))
	assert.Equal(t, 1, hits[14 /*P.PacketTypePublicSubkey*/])
	assert.Equal(t, 1, len(key.subkeys[0].signatures))
	assert.Equal(t, 4, len(hits))
}
