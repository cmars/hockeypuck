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
	"crypto/sha256"
	"encoding/ascii85"
	"errors"

	"golang.org/x/crypto/openpgp/packet"
	"gopkg.in/errgo.v1"
)

var ErrInvalidPacketType error = errors.New("Invalid packet type")
var ErrPacketRecordState error = errors.New("Packet record state has not been properly initialized")

/*
// PacketState indicates the validity of the public key material and special
// policies that may apply to it. The lower 16 bits are either neutral policy
// or positive validation indicators. The upper 16 bits indicate validation failure
// that the key material is either invalid, unverifiable or failed to meet some policy
// criteria.
type PacketState int

const (
	// Bits 0-15 indicate positive verification status and public key policies

	// Key material has been registered with Hockeypuck by the key owner,
	// who has signed a nonced challenge message with the associated private key.
	PacketStateRegistered = 1 << 0

	// Key material is cloaked. Hockeypuck will respond as if the key does not exist
	// unless the HKP request has proper authentication.
	PacketStateCloaked = 1 << 1

	// Signature has been checked and verified
	PacketStateSigOk = 1 << 2

	// Bits 16-23 indicate verification failure of the key material.

	// Key material is banned from HKP results unconditionally. Could be signature
	// graphiti or other unwanted content.
	PacketStateSpam = 1 << 16

	// Key material is considered to be abandoned according to keyserver policy.
	PacketStateAbandoned = 1 << 17

	// Key material lacks a valid, non-expired self-signature
	PacketStateNoSelfSig = 1 << 18

	// Subkey material lacks a valid, non-expired binding-signature
	PacketStateNoBindingSig = 1 << 19

	// Public key is unsupported (unknown algorithm code, etc.)
	PacketStateUnsuppPubkey = 1 << 20
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
*/

type Packet struct {

	// UUID is a universally unique identifier string for this packet. Not
	// necessarily a standard UUID format though.
	UUID string

	// Tag indicates the OpenPGP package tag type.
	Tag uint8

	// Valid indicates whether Hockeypuck is able to parse the contents of this
	// packet or if it is unsupported/malformed key material.
	Valid bool

	// Count indicates the number of times this packet occurs in the keyring.
	Count int

	// Packet contains the raw packet bytes.
	Packet []byte
}

const packetTag = "{other}"

func ParseOther(op *packet.OpaquePacket, parentID string) (*Packet, error) {
	var buf bytes.Buffer
	err := op.Serialize(&buf)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return &Packet{
		UUID:   scopedDigest([]string{parentID}, packetTag, buf.Bytes()),
		Tag:    op.Tag,
		Packet: buf.Bytes(),
		Valid:  false,
	}, nil
}

// packetNode defines a tree-like hierarchy by which OpenPGP packets can be
// usefully traversed.
type packetNode interface {
	contents() []packetNode
	packet() *Packet
	removeDuplicate(parent packetNode, target packetNode) error
	uuid() string
}

type signable interface {
	appendSignature(*Signature)

	packetNode
}

// packet implements the packetNode interface.
func (p *Packet) packet() *Packet {
	return p
}

// contents implements the packetNode interface for default unclassified packets.
func (p *Packet) contents() []packetNode {
	return []packetNode{p}
}

func (p *Packet) uuid() string {
	return p.UUID
}

func (p *Packet) removeDuplicate(parent packetNode, dup packetNode) error {
	dupPacket, ok := dup.(*Packet)
	if !ok {
		return errgo.Newf("invalid packet duplicate: %+v", dup)
	}
	switch ppkt := parent.(type) {
	case *Pubkey:
		ppkt.Others = packetSlice(ppkt.Others).without(dupPacket)
	case *Subkey:
		ppkt.Others = packetSlice(ppkt.Others).without(dupPacket)
	case *UserID:
		ppkt.Others = packetSlice(ppkt.Others).without(dupPacket)
	case *UserAttribute:
		ppkt.Others = packetSlice(ppkt.Others).without(dupPacket)
	}
	return nil
}

type packetSlice []*Packet

func (ps packetSlice) without(target *Packet) []*Packet {
	var result []*Packet
	for _, packet := range ps {
		if packet != target {
			result = append(result, packet)
		}
	}
	return result
}

func newOpaquePacket(buf []byte) (*packet.OpaquePacket, error) {
	r := packet.NewOpaqueReader(bytes.NewBuffer(buf))
	return r.Next()
}

type opaquePacketSlice []*packet.OpaquePacket

func (ps opaquePacketSlice) Len() int {
	return len(ps)
}

func (ps opaquePacketSlice) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

func (ps opaquePacketSlice) Less(i, j int) bool {
	cmp := int32(ps[i].Tag) - int32(ps[j].Tag)
	if cmp < 0 {
		return true
	} else if cmp > 0 {
		return false
	}
	return bytes.Compare(ps[i].Contents, ps[j].Contents) < 0
}

func toAscii85String(buf []byte) string {
	out := bytes.NewBuffer(nil)
	enc := ascii85.NewEncoder(out)
	enc.Write(buf)
	enc.Close()
	return out.String()
}

func scopedDigest(parents []string, tag string, packet []byte) string {
	h := sha256.New()
	for i := range parents {
		h.Write([]byte(parents[i]))
		h.Write([]byte(tag))
	}
	h.Write(packet)
	return toAscii85String(h.Sum(nil))
}
