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
	"encoding/binary"
	"encoding/hex"
	"time"

	"golang.org/x/crypto/openpgp/packet"
	"gopkg.in/errgo.v1"

	"github.com/hockeypuck/hockeypuck/util"
)

type Signature struct {
	Packet

	SigType      int
	RIssuerKeyID string
	Creation     time.Time
	Expiration   time.Time
}

const sigTag = "{sig}"

func (sig *Signature) removeDuplicate(parent packetNode, dup packetNode) error {
	dupSig, ok := dup.(*Signature)
	if !ok {
		return errgo.Newf("invalid packet duplicate: %+v", dup)
	}
	switch ppkt := parent.(type) {
	case *Pubkey:
		ppkt.Signatures = sigSlice(ppkt.Signatures).without(dupSig)
	case *Subkey:
		ppkt.Signatures = sigSlice(ppkt.Signatures).without(dupSig)
	case *UserID:
		ppkt.Signatures = sigSlice(ppkt.Signatures).without(dupSig)
	case *UserAttribute:
		ppkt.Signatures = sigSlice(ppkt.Signatures).without(dupSig)
	}
	return nil
}

type sigSlice []*Signature

func (ss sigSlice) without(target *Signature) []*Signature {
	var result []*Signature
	for _, sig := range ss {
		if sig != target {
			result = append(result, sig)
		}
	}
	return result
}

func ParseSignature(op *packet.OpaquePacket, pubkeyUUID, scopedUUID string) (*Signature, error) {
	var buf bytes.Buffer
	var err error

	if err = op.Serialize(&buf); err != nil {
		return nil, errgo.Mask(err)
	}
	sig := &Signature{
		Packet: Packet{
			UUID:   scopedDigest([]string{pubkeyUUID, scopedUUID}, sigTag, buf.Bytes()),
			Tag:    op.Tag,
			Packet: buf.Bytes(),
		},
	}

	// Attempt to parse the opaque packet into a public key type.
	err = sig.parse(op)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	sig.Valid = true
	return sig, nil
}

func (sig *Signature) parse(op *packet.OpaquePacket) error {
	p, err := op.Parse()
	if err != nil {
		return errgo.Mask(err)
	}

	switch s := p.(type) {
	case *packet.Signature:
		return sig.setSignature(s)
	case *packet.SignatureV3:
		return sig.setSignatureV3(s)
	}
	return errgo.Mask(ErrInvalidPacketType, errgo.Any)
}

func (sig *Signature) setSignature(s *packet.Signature) error {
	if s.IssuerKeyId == nil {
		return errgo.New("missing issuer key ID")
	}
	sig.Creation = s.CreationTime
	sig.SigType = int(s.SigType)
	// Extract the issuer key id
	var issuerKeyId [8]byte
	if s.IssuerKeyId != nil {
		binary.BigEndian.PutUint64(issuerKeyId[:], *s.IssuerKeyId)
		sigKeyId := hex.EncodeToString(issuerKeyId[:])
		sig.RIssuerKeyID = util.Reverse(sigKeyId)
	}
	// Expiration time
	if s.SigLifetimeSecs != nil {
		sig.Expiration = s.CreationTime.Add(
			time.Duration(*s.SigLifetimeSecs) * time.Second)
	}
	return nil
}

func (sig *Signature) setSignatureV3(s *packet.SignatureV3) error {
	sig.Creation = s.CreationTime
	// V3 packets do not have an expiration time
	sig.SigType = int(s.SigType)
	// Extract the issuer key id
	var issuerKeyId [8]byte
	binary.BigEndian.PutUint64(issuerKeyId[:], s.IssuerKeyId)
	sigKeyId := hex.EncodeToString(issuerKeyId[:])
	sig.RIssuerKeyID = util.Reverse(sigKeyId)
	return nil
}

/*
type Signature struct {
	ScopedDigest       string         `db:"uuid"`        // immutable
	Creation           time.Time      `db:"creation"`    // immutable
	Expiration         time.Time      `db:"expiration"`  // immutable
	State              int            `db:"state"`       // mutable
	Packet             []byte         `db:"packet"`      // immutable
	SigType            int            `db:"sig_type"`    // immutable
	RIssuerKeyId       string         `db:"signer"`      // immutable
	RIssuerFingerprint sql.NullString `db:"signer_uuid"` // mutable
	RevSigDigest       sql.NullString `db:"revsig_uuid"` // mutable

	/ * Containment references * /

	PubkeyUuid sql.NullString `db:"pubkey_uuid"`
	SubkeyUuid sql.NullString `db:"subkey_uuid"`
	UidUuid    sql.NullString `db:"uid_uuid"`
	UatUuid    sql.NullString `db:"uat_uuid"`
	SigUuid    sql.NullString `db:"sig_uuid"`

	/ * Cross-references * /

	revSig *Signature

	/ * Parsed packet data * /

	Signature   *packet.Signature
	SignatureV3 *packet.SignatureV3
}

func (sig *Signature) IssuerKeyId() string {
	return util.Reverse(sig.RIssuerKeyId)
}

func (sig *Signature) IssuerShortId() string {
	return sig.IssuerKeyId()[8:16]
}

func (sig *Signature) IssuerFingerprint() string {
	return util.Reverse(sig.RIssuerFingerprint.String)
}

func (sig *Signature) calcScopedDigest(pubkey *Pubkey, scope string) string {
	h := sha256.New()
	h.Write([]byte(pubkey.RFingerprint))
	h.Write([]byte("{sig}"))
	h.Write([]byte(scope))
	h.Write([]byte("{sig}"))
	h.Write(sig.Packet)
	return toAscii85String(h.Sum(nil))
}

func (sig *Signature) Serialize(w io.Writer) error {
	_, err := w.Write(sig.Packet)
	return errgo.Mask(err)
}

func (sig *Signature) Uuid() string { return sig.ScopedDigest }

func (sig *Signature) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(sig.Packet)
}

func (sig *Signature) GetPacket() (packet.Packet, error) {
	var p packet.Packet
	if sig.Signature != nil {
		p = sig.Signature
	} else if sig.SignatureV3 != nil {
		p = sig.SignatureV3
	} else {
		return nil, ErrPacketRecordState
	}
	return p, nil
}

func (sig *Signature) setPacket(p packet.Packet) error {
	switch s := p.(type) {
	case *packet.Signature:
		sig.Signature = s
	case *packet.SignatureV3:
		sig.SignatureV3 = s
	default:
		return ErrInvalidPacketType
	}
	return nil
}

func (sig *Signature) Read() error {
	buf := bytes.NewBuffer(sig.Packet)
	p, err := packet.Read(buf)
	if err != nil {
		return errgo.Mask(err)
	}
	return sig.setPacket(p)
}

func (sig *Signature) GetSignature() (packet.Packet, error) {
	buf := bytes.NewBuffer(sig.Packet)
	return packet.Read(buf)
}

func NewSignature(op *packet.OpaquePacket) (*Signature, error) {
	var buf bytes.Buffer
	if err := op.Serialize(&buf); err != nil {
		return nil, errgo.Mask(err)
	}
	sig := &Signature{Packet: buf.Bytes()}
	p, err := op.Parse()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if err = sig.setPacket(p); err != nil {
		return nil, errgo.Mask(err)
	}
	if sig.Signature != nil {
		sig.initV4()
	} else if sig.SignatureV3 != nil {
		sig.initV3()
	} else {
		return nil, ErrInvalidPacketType
	}
	return sig, nil
}

func (sig *Signature) Visit(visitor PacketVisitor) error {
	return visitor(sig)
}

func (sig *Signature) IsPrimary() bool {
	return sig.Signature != nil && sig.Signature.IsPrimaryId != nil && *sig.Signature.IsPrimaryId
}
*/
