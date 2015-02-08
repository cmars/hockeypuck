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
	"io"
	"testing"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	gc "gopkg.in/check.v1"
)

func Test(t *testing.T) { gc.TestingT(t) }

type SamplePacketSuite struct{}

var _ = gc.Suite(&SamplePacketSuite{})

func (s *SamplePacketSuite) TestVerifyUserAttributeSig(c *gc.C) {
	key := MustInputAscKey(c, "uat.asc")
	c.Assert(key.UserAttributes, gc.HasLen, 1)
	Deduplicate(key)
	c.Assert(key.UserAttributes, gc.HasLen, 1)
	uat := key.UserAttributes[0]
	c.Assert(uat.Images, gc.HasLen, 1)
	// TODO: check contents
}

/*
const SksExampleShortID = "ce353cf4"
const SKS_DIGEST__REFERENCE = "da84f40d830a7be2a3c0b7f2e146bfaa"

func (s *SamplePacketSuite) TestSksDigest(c *gc.C) {
	key := MustInputAscKey(c, "sksdigest.asc")
	assert.Equal(t, SKS_DIGEST__SHORTID, key.ShortId())
	assert.Equal(t, SKS_DIGEST__REFERENCE, key.Md5)
}
*/

func (s *SamplePacketSuite) TestUatRtt(c *gc.C) {
	f := MustInput(c, "uat.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)
	var p packet.Packet
	for {
		p, err = packet.Read(block.Body)
		if err != nil {
			c.Assert(err, gc.Equals, io.EOF)
			break
		}

		uat, ok := p.(*packet.UserAttribute)
		if ok {
			var buf bytes.Buffer
			uat.Serialize(&buf)
			or := packet.NewOpaqueReader(bytes.NewBuffer(buf.Bytes()))
			op, _ := or.Next()
			c.Assert(buf.Bytes()[3:], gc.DeepEquals, op.Contents)
		}
	}
}

func (s *SamplePacketSuite) TestReadKey0ff16c87(c *gc.C) {
	f := MustInput(c, "0ff16c87.asc")
	block, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)
	var key *Pubkey
	for keyRead := range ReadKeys(block.Body) {
		key = keyRead.Pubkey
	}
	c.Assert(key, gc.NotNil)
	c.Assert(key.UserIDs, gc.HasLen, 9)
	c.Assert(key.UserAttributes, gc.HasLen, 0)
	c.Assert(key.Subkeys, gc.HasLen, 1)
}
