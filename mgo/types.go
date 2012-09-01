/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012  Casey Marshall

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

package mgo

import (
	"bytes"
	"launchpad.net/hockeypuck"
	"bitbucket.org/cmars/go.crypto/openpgp/packet"
)

type PacketObject interface {
	GetPacket() []byte
	SetPacket(op *packet.OpaquePacket)
	GetDigest() string
	Traverse(pktObjChan chan PacketObject)
	Parse() (packet.Packet, error)
}

type Signable interface {
	AppendSig(sig* Signature)
}

type PubKey struct {
	Fingerprint string
	KeyId []byte
	ShortId []byte
	Algorithm int
	KeyLength uint16
	Signatures []*Signature
	Identities []*UserId
	SubKeys []*SubKey
	Packet []byte
	Digest string
}

func (pubKey *PubKey) AppendSig(sig *Signature) {
	pubKey.Signatures = append(pubKey.Signatures, sig)
}

func (o *PubKey) GetPacket() []byte {
	return o.Packet
}

func (o *PubKey) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (o *PubKey) GetDigest() string {
	return o.Digest
}

func (o *PubKey) Traverse(c chan PacketObject) {
	c <- o
	for _, s := range o.Signatures {
		s.Traverse(c)
	}
	for _, u := range o.Identities {
		u.Traverse(c)
	}
	for _, s := range o.SubKeys {
		s.Traverse(c)
	}
}

func (o *PubKey) Parse() (packet.Packet, error) {
	buf := bytes.NewBuffer(o.GetPacket())
	opr := packet.NewOpaqueReader(buf)
	opkt, err := opr.Next()
	if err == nil {
		return opkt.Parse()
	}
	return nil, err
}

type Signature struct {
	SigType int
	IssuerKeyId []byte
	Packet []byte
	Digest string
}

func (o *Signature) GetPacket() []byte {
	return o.Packet
}

func (o *Signature) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (o *Signature) GetDigest() string {
	return o.Digest
}

func (o *Signature) Traverse(c chan PacketObject) {
	c <- o
}

func (o *Signature) Parse() (packet.Packet, error) {
	buf := bytes.NewBuffer(o.GetPacket())
	opr := packet.NewOpaqueReader(buf)
	opkt, err := opr.Next()
	if err == nil {
		return opkt.Parse()
	}
	return nil, err
}

type UserId struct {
	Id string
	Keywords []string
	Signatures []*Signature
	Attributes []*UserAttribute
	Packet []byte
	Digest string
}

func (userId *UserId) AppendSig(sig *Signature) {
	userId.Signatures = append(userId.Signatures, sig)
}

func (o *UserId) GetPacket() []byte {
	return o.Packet
}

func (o *UserId) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (o *UserId) Traverse(c chan PacketObject) {
	c <- o
	for _, s := range o.Signatures {
		s.Traverse(c)
	}
	for _, a := range o.Attributes {
		a.Traverse(c)
	}
}

func (o *UserId) Parse() (packet.Packet, error) {
	buf := bytes.NewBuffer(o.GetPacket())
	opr := packet.NewOpaqueReader(buf)
	opkt, err := opr.Next()
	if err == nil {
		return opkt.Parse()
	}
	return nil, err
}

func (o *UserId) GetDigest() string {
	return o.Digest
}

type UserAttribute struct {
	Signatures []*Signature
	Packet []byte
	Digest string
}

func (o *UserAttribute) GetPacket() []byte {
	return o.Packet
}

func (o *UserAttribute) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (userAttr *UserAttribute) AppendSig(sig *Signature) {
	userAttr.Signatures = append(userAttr.Signatures, sig)
}

func (o *UserAttribute) GetDigest() string {
	return o.Digest
}

func (o *UserAttribute) Traverse(c chan PacketObject) {
	c <- o
	for _, s := range o.Signatures {
		s.Traverse(c)
	}
}

func (o *UserAttribute) Parse() (packet.Packet, error) {
	buf := bytes.NewBuffer(o.GetPacket())
	opr := packet.NewOpaqueReader(buf)
	opkt, err := opr.Next()
	if err == nil {
		return opkt.Parse()
	}
	return nil, err
}

type SubKey struct {
	Fingerprint string
	Algorithm int
	KeyLength uint16
	Signatures []*Signature
	Packet []byte
	Digest string
}

func (subKey *SubKey) AppendSig(sig *Signature) {
	subKey.Signatures = append(subKey.Signatures, sig)
}

func (o *SubKey) GetPacket() []byte {
	return o.Packet
}

func (o *SubKey) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (o *SubKey) GetDigest() string {
	return o.Digest
}

func (o *SubKey) Traverse(c chan PacketObject) {
	c <- o
	for _, s := range o.Signatures {
		s.Traverse(c)
	}
}

func (o *SubKey) Parse() (packet.Packet, error) {
	buf := bytes.NewBuffer(o.GetPacket())
	opr := packet.NewOpaqueReader(buf)
	opkt, err := opr.Next()
	if err == nil {
		return opkt.Parse()
	}
	return nil, err
}
