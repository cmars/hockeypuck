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
	"sort"
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
	var packets2 []*packet.OpaquePacket
	for opkt := range IterOpaquePackets(key) {
		packets2 = append(packets2, opkt.OpaquePacket)
	}
	sort.Sort(sksPacketSorter{packets})
	sort.Sort(sksPacketSorter{packets2})
	t.Logf("Raw packets:")
	for _, op := range packets {
		t.Logf("%x", op.Contents)
	}
	t.Logf("Processed packets:")
	for _, op := range packets2 {
		t.Logf("%x", op.Contents)
	}
	missingPkt, err := packets[len(packets)-1].Parse()
	t.Log(missingPkt)
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
