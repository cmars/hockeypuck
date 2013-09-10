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
	"errors"
	"io"
)

var ErrInvalidPacketType error = errors.New("Invalid packet type")
var ErrPacketRecordState error = errors.New("Packet record state has not been properly initialized")

type PacketState int

const (
	// Packet is syntactially valid and parses according to OpenPGP specifications.
	// No policy or semantic interpretation of the key material has been applied.
	PacketStateOk = 0

	// 1xx packet states reflect policy dispositions of the public key material
	// made external to the OpenPGP contents.

	// Key material has been registered with Hockeypuck by the key owner,
	// who has signed a nonced challenge message with the associated private key.
	PacketStateRegistered = 100
	// Key material is cloaked. Hockeypuck will respond as if the key does not exist
	// unless the HKP request has proper authentication.
	PacketStateCloaked = iota
	// Key material is banned from HKP results unconditionally. Could be signature
	// graphiti or other unwanted content.
	PacketStateBanned = iota
	// Key material is considered to be abandoned according to keyserver policy.
	PacketStateAbandoned = iota
	// Key material is rejected according to keyserver policy. For example,
	// a keyserver could reject all keys and signatures without expirations.
	PacketStateRejected = iota

	// 4xx packet states indicate semantic problems with the key material, rendering it
	// unusable.

	// General error code for semantically invalid key
	PacketStateInvalid = 400
	// Key material has a verified revocation certificate
	PacketStateRevoked = iota
	// Key material lacks a verified self-signature
	PacketStateMissingSelfSig = iota
)

type PacketVisitor func(PacketRecord) error

type PacketRecord interface {
	GetOpaquePacket() (*packet.OpaquePacket, error)
	GetPacket() (packet.Packet, error)
	setPacket(packet.Packet) error
	Read() error
	Serialize(w io.Writer) error
	Visit(PacketVisitor) error
}

type publicKeyRecord interface {
	publicKey() *packet.PublicKey
	publicKeyV3() *packet.PublicKeyV3
}

type Signable interface {
	AddSignature(*Signature)
}

func toOpaquePacket(buf []byte) (*packet.OpaquePacket, error) {
	r := packet.NewOpaqueReader(bytes.NewBuffer(buf))
	return r.Next()
}

type packetSlice []*packet.OpaquePacket

func (ps packetSlice) Len() int {
	return len(ps)
}

func (ps packetSlice) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

type sksPacketSorter struct{ packetSlice }

func (sps sksPacketSorter) Less(i, j int) bool {
	cmp := int32(sps.packetSlice[i].Tag) - int32(sps.packetSlice[j].Tag)
	if cmp < 0 {
		return true
	} else if cmp > 0 {
		return false
	}
	return bytes.Compare(sps.packetSlice[i].Contents, sps.packetSlice[j].Contents) < 0
}
