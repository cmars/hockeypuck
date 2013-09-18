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

	// Key material has been registered with Hockeypuck by the key owner,
	// who has signed a nonced challenge message with the associated private key.
	PacketStateRegistered = 1 << 0
	// Key material is cloaked. Hockeypuck will respond as if the key does not exist
	// unless the HKP request has proper authentication.
	PacketStateCloaked = 1 << 1
	// Key material is banned from HKP results unconditionally. Could be signature
	// graphiti or other unwanted content.
	PacketStateSpam = 1 << 2
	// Key material is considered to be abandoned according to keyserver policy.
	PacketStateAbandoned = 1 << 3

	// Bits 4-15 reserved for additional policies.

	// Bits 16-23 indicate signature verification failure on the key material

	// Key material lacks a valid, non-expired self-signature
	PacketStateNoSelfSig = 1 << 16

	// Subkey material lacks a valid, non-expired binding-signature
	PacketStateNoBindingSig = 1 << 17

	// Public key is unsupported (unknown algorithm code, etc.)
	PacketStateUnsuppPubkey = 1 << 18
)

type PacketVisitor func(PacketRecord) error

type PacketRecord interface {
	GetOpaquePacket() (*packet.OpaquePacket, error)
	GetPacket() (packet.Packet, error)
	Read() error
	Serialize(w io.Writer) error
	setPacket(packet.Packet) error
	Uuid() string
	Visit(PacketVisitor) error
}

type publicKeyRecord interface {
	publicKey() *packet.PublicKey
	publicKeyV3() *packet.PublicKeyV3
}

type Signable interface {
	AddSignature(*Signature)
	RemoveSignature(*Signature)
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
