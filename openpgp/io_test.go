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
	"bytes"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyUserAttributeSig(t *testing.T) {
	key := MustInputAscKey(t, "uat.asc")
	assert.Equal(t, 1, len(key.userAttributes), "Failed to read user attribute")
	Resolve(key)
	assert.Equal(t, 1, len(key.userAttributes), "Failed to validate user attribute")
	uat := key.userAttributes[0]
	imageDats := uat.UserAttribute.ImageData()
	assert.Equal(t, 1, len(imageDats), "Expected 1 image in uat, found", len(imageDats))
	// TODO: check contents
}

const SKS_DIGEST__SHORTID = "ce353cf4"
const SKS_DIGEST__REFERENCE = "da84f40d830a7be2a3c0b7f2e146bfaa"

func TestSksDigest(t *testing.T) {
	key := MustInputAscKey(t, "sksdigest.asc")
	assert.Equal(t, SKS_DIGEST__SHORTID, key.ShortId())
	assert.Equal(t, SKS_DIGEST__REFERENCE, key.Md5)
}

func TestUatRtt(t *testing.T) {
	f := MustInput(t, "uat.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	var p packet.Packet
	for {
		p, err = packet.Read(block.Body)
		if err != nil {
			break
		}
		if uat, is := p.(*packet.UserAttribute); is {
			var buf bytes.Buffer
			uat.Serialize(&buf)
			or := packet.NewOpaqueReader(bytes.NewBuffer(buf.Bytes()))
			op, _ := or.Next()
			assert.Equal(t, buf.Bytes()[3:], op.Contents)
		}
	}
}

func TestReadKey0ff16c87(t *testing.T) {
	f := MustInput(t, "0ff16c87.asc")
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	var key *Pubkey
	for keyRead := range ReadKeys(block.Body) {
		key = keyRead.Pubkey
	}
	assert.NotNil(t, key)
	key.Visit(func(rec PacketRecord) error {
		_, err = rec.GetOpaquePacket()
		switch r := rec.(type) {
		case *Pubkey:
			assert.NotEmpty(t, r.Packet)
		case *Subkey:
			assert.NotEmpty(t, r.Packet)
		case *Signature:
			assert.NotEmpty(t, r.Packet)
		case *UserId:
			assert.NotEmpty(t, r.Packet)
		case *UserAttribute:
			assert.NotEmpty(t, r.Packet)
		}
		assert.Nil(t, err)
		return nil
	})
}
