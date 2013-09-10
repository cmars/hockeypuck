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
	"bytes"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto/sha256"
	"io"
	"time"
)

// Unsupported represents key material we receive from
// a reconciliation peer that we cannot validate. Hockeypuck
// will store such key material until such time it can
// parse and interpret correctly.
type Unsupported struct {
	ScopedDigest string    `db:"uuid"`
	Creation     time.Time `db:"creation"`    // immutable
	Expiration   time.Time `db:"expiration"`  // mutable
	State        int       `db:"state"`       // mutable
	Packet       []byte    `db:"packet"`      // immutable
	PubkeyRFP    string    `db:"pubkey_uuid"` // immutable
	Tag          int       `db:"tag"`         // immutable
	Reason       string    `db:"reason"`      // mutable

	/* Parsed packet data */

	OpaquePacket *packet.OpaquePacket
}

func (un *Unsupported) calcScopedDigest(pubkey *Pubkey) string {
	h := sha256.New()
	h.Write([]byte(pubkey.RFingerprint))
	h.Write(un.Packet)
	return toAscii85String(h.Sum(nil))
}

func (un *Unsupported) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(un.Packet)
}

func (un *Unsupported) GetPacket() (packet.Packet, error) {
	if un.OpaquePacket != nil {
		return un.OpaquePacket, nil
	}
	return nil, ErrPacketRecordState
}

func (un *Unsupported) setPacket(p packet.Packet) (err error) {
	var is bool
	if un.OpaquePacket, is = p.(*packet.OpaquePacket); !is {
		err = ErrInvalidPacketType
	}
	return
}

func (un *Unsupported) Read() (err error) {
	buf := bytes.NewBuffer(un.Packet)
	var p packet.Packet
	if p, err = packet.Read(buf); err != nil {
		return err
	}
	err = un.setPacket(p)
	return
}

func NewUnsupported(p packet.Packet) (un *Unsupported, err error) {
	un = new(Unsupported)
	if err = un.setPacket(p); err != nil {
		return
	}
	return un, un.init()
}

func (un *Unsupported) init() (err error) {
	var buf bytes.Buffer
	if err = un.OpaquePacket.Serialize(&buf); err != nil {
		return
	}
	un.Packet = buf.Bytes()
	un.Tag = int(un.OpaquePacket.Tag)
	if un.OpaquePacket.Reason != nil {
		un.Reason = un.OpaquePacket.Reason.Error()
	}
	return
}

func (un *Unsupported) Serialize(w io.Writer) error {
	_, err := w.Write(un.Packet)
	return err
}

func (un *Unsupported) Visit(visitor PacketVisitor) error {
	return visitor(un)
}
