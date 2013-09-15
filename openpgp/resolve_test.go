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
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto/md5"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestBadSelfSigUid(t *testing.T) {
	key := MustInputAscKey(t, "badselfsig.asc")
	Resolve(key)
	for _, uid := range key.userIds {
		assert.True(t, !strings.Contains(uid.UserId.Id, "Karneef"))
	}
}

func TestDupSig(t *testing.T) {
	f := MustInput(t, "252B8B37.dupsig.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	r := packet.NewOpaqueReader(block.Body)
	var packets []*packet.OpaquePacket
	for {
		if op, err := r.Next(); err != nil {
			break
		} else {
			packets = append(packets, op)
		}
	}
	sksDigest := sksDigestOpaque(packets, md5.New())
	assert.Equal(t, sksDigest, "6d57b48c83d6322076d634059bb3b94b")
	key := MustInputAscKey(t, "252B8B37.dupsig.asc")
	assert.Equal(t, key.Md5, "6d57b48c83d6322076d634059bb3b94b")
}

func TestPrimaryUidSelection(t *testing.T) {
	key := MustInputAscKey(t, "lp1195901.asc")
	Resolve(key)
	assert.NotNil(t, key.primaryUid)
	// Primary UID
	assert.Equal(t, key.primaryUid.Keywords, "Phil Pennock <phil.pennock@spodhuis.org>")
	for _, uid := range key.userIds {
		if uid.Keywords == "pdp@spodhuis.demon.nl" {
			// This uid sig is revoked
			assert.NotNil(t, uid.revSig)
		}
	}
	key = MustInputAscKey(t, "lp1195901_2.asc")
	Resolve(key)
	assert.NotNil(t, key.primaryUid)
	assert.Equal(t, key.primaryUid.Keywords, "Phil Pennock <phil.pennock@globnix.org>")
}

func TestSortPrimaryUid(t *testing.T) {
	key := MustInputAscKey(t, "lp1195901.asc")
	Resolve(key)
	Sort(key)
	expect := []string{
		"Phil Pennock <phil.pennock@spodhuis.org>",
		"Phil Pennock <phil.pennock@globnix.org>",
		"Phil Pennock <pdp@spodhuis.org>",
		"Phil Pennock <pdp@exim.org>",
		"Phil Pennock <pdp@spodhuis.demon.nl>"}
	for i := range key.userIds {
		assert.Equal(t, expect[i], key.userIds[i].Keywords)
	}
}

func TestPrimaryUidFallback(t *testing.T) {
	f := MustInput(t, "snowcrash.gpg")
	var key *Pubkey
	for keyRead := range ReadKeys(f) {
		assert.Nil(t, keyRead.Error)
		key = keyRead.Pubkey
	}
	assert.NotNil(t, key)
	assert.NotEmpty(t, key.PrimaryUid)
	t.Log(key.PrimaryUid)
}

func TestUnsupp(t *testing.T) {
	f := MustInput(t, "snowcrash.gpg")
	var key *Pubkey
	for keyRead := range ReadKeys(f) {
		assert.Nil(t, keyRead.Error)
		key = keyRead.Pubkey
	}
	assert.NotNil(t, key)
	assert.NotEmpty(t, key.unsupported)
	for _, unsupp := range key.unsupported {
		assert.NotEmpty(t, unsupp.PrevDigest)
		t.Log(unsupp.PrevDigest)
	}
}

func TestMissingUidFk(t *testing.T) {
	key := MustInputAscKey(t, "d7346e26.asc")
	t.Log(key)
}
