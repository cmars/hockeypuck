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
	"database/sql"
	"encoding/ascii85"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"launchpad.net/hockeypuck/util"
	"log"
	"time"
)

var ErrInvalidPacketType error = errors.New("Invalid packet type")

type PacketVisitor func(PacketRecord) error

type PacketRecord interface {
	GetOpaquePacket() (*packet.OpaquePacket, error)
	GetPacket() (packet.Packet, error)
	SetPacket(packet.Packet) error
	Visit(PacketVisitor) error
}

type Signable interface {
	AddSignature(*Signature)
}

func toOpaquePacket(buf []byte) (*packet.OpaquePacket, error) {
	r := packet.NewOpaqueReader(bytes.NewBuffer(buf))
	return r.Next()
}

// Model representing an OpenPGP public key packets.
// Searchable fields are extracted from the packet key material
// stored in Packet, for database indexing.
type Pubkey struct {
	RFingerprint   string           `db:"uuid"`        // immutable
	Creation       time.Time        `db:"creation"`    // immutable
	Expiration     time.Time        `db:"expiration"`  // mutable
	State          int              `db:"state"`       // mutable
	Packet         []byte           `db:"packet"`      // immutable
	Ctime          time.Time        `db:"ctime"`       // immutable
	Mtime          time.Time        `db:"mtime"`       // mutable
	Md5            string           `db:"md5"`         // mutable
	Sha256         string           `db:"sha256"`      // mutable
	RevSigDigest   sql.NullString   `db:"revsig_uuid"` // mutable
	PrimaryUid     sql.NullString   `db:"primary_uid"` // mutable
	PrimaryUat     sql.NullString   `db:"primary_uat"` // mutable
	Algorithm      int              `db:"algorithm"`   // immutable
	BitLen         int              `db:"bit_len"`     // immutable
	signatures     []*Signature     `db:"-"`
	subkeys        []*Subkey        `db:"-"`
	userIds        []*UserId        `db:"-"`
	userAttributes []*UserAttribute `db:"-"`
	revSig         *Signature       `db:"-"`
	primaryUid     *UserId          `db:"-"`
	primaryUidSig  *Signature       `db:"-"`
	primaryUat     *UserAttribute   `db:"-"`
	primaryUatSig  *Signature       `db:"-"`
}

func (pubkey *Pubkey) Fingerprint() string {
	return util.Reverse(pubkey.RFingerprint)
}

func (pubkey *Pubkey) KeyId() string {
	return util.Reverse(pubkey.RFingerprint[:16])
}

func (pubkey *Pubkey) ShortId() string {
	return util.Reverse(pubkey.RFingerprint[:8])
}

func (pubkey *Pubkey) Serialize(w io.Writer) error {
	_, err := w.Write(pubkey.Packet)
	return err
}

func (pubkey *Pubkey) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(pubkey.Packet)
}

func (pubkey *Pubkey) GetPacket() (packet.Packet, error) {
	return pubkey.GetPublicKey()
}

func (pubkey *Pubkey) GetPublicKey() (*packet.PublicKey, error) {
	buf := bytes.NewBuffer(pubkey.Packet)
	pk, err := packet.Read(buf)
	return pk.(*packet.PublicKey), err
}

func (pubkey *Pubkey) SetPacket(p packet.Packet) error {
	pk, is := p.(*packet.PublicKey)
	if !is {
		return ErrInvalidPacketType
	}
	return pubkey.SetPublicKey(pk)
}

func (pubkey *Pubkey) SetPublicKey(pk *packet.PublicKey) error {
	buf := bytes.NewBuffer(nil)
	err := pk.Serialize(buf)
	if err != nil {
		return err
	}
	fingerprint := Fingerprint(pk)
	bitLen, err := pk.BitLength()
	if err != nil {
		return err
	}
	if pk.IsSubkey {
		log.Println("Expected primary public key packet, got sub-key")
		return ErrInvalidPacketType
	}
	pubkey.Packet = buf.Bytes()
	pubkey.RFingerprint = util.Reverse(fingerprint)
	pubkey.Creation = pk.CreationTime
	pubkey.Expiration = NeverExpires
	pubkey.Algorithm = int(pk.PubKeyAlgo)
	pubkey.BitLen = int(bitLen)
	return nil
}

func (pubkey *Pubkey) Visit(visitor PacketVisitor) (err error) {
	err = visitor(pubkey)
	if err != nil {
		return
	}
	for _, sig := range pubkey.signatures {
		err = sig.Visit(visitor)
		if err != nil {
			return
		}
	}
	for _, uid := range pubkey.userIds {
		err = uid.Visit(visitor)
		if err != nil {
			return
		}
	}
	for _, uat := range pubkey.userAttributes {
		err = uat.Visit(visitor)
		if err != nil {
			return
		}
	}
	for _, subkey := range pubkey.subkeys {
		err = subkey.Visit(visitor)
		if err != nil {
			return
		}
	}
	return
}

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
	revSig             *Signature     `db:"-"`
}

func (sig *Signature) IssuerKeyId() string {
	return util.Reverse(sig.RIssuerKeyId)
}

func (sig *Signature) IssuerFingerprint() string {
	return util.Reverse(sig.RIssuerFingerprint.String)
}

func toAscii85String(buf []byte) string {
	out := bytes.NewBuffer(nil)
	enc := ascii85.NewEncoder(out)
	enc.Write(buf)
	enc.Close()
	return out.String()
}

func (sig *Signature) calcScopedDigest(pubkey *Pubkey, scope string) string {
	h := sha256.New()
	h.Write([]byte(pubkey.RFingerprint))
	h.Write([]byte(scope))
	h.Write(sig.Packet)
	return toAscii85String(h.Sum(nil))
}

func (sig *Signature) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(sig.Packet)
}

func (sig *Signature) GetPacket() (packet.Packet, error) {
	return sig.GetSignature()
}

func (sig *Signature) GetSignature() (packet.Packet, error) {
	buf := bytes.NewBuffer(sig.Packet)
	return packet.Read(buf)
}

func (sig *Signature) getSignatureV4() (*packet.Signature, error) {
	sp, err := sig.GetSignature()
	if err != nil {
		return nil, err
	}
	if s, is := sp.(*packet.Signature); is {
		return s, nil
	} else {
		return nil, ErrInvalidPacketType
	}
}

func (sig *Signature) SetPacket(p packet.Packet) error {
	return sig.SetSignature(p)
}

func (sig *Signature) SetSignature(p packet.Packet) error {
	switch s := p.(type) {
	case *packet.Signature:
		return sig.setPacketV4(s)
	}
	return ErrInvalidPacketType
}

func (sig *Signature) setPacketV4(s *packet.Signature) error {
	buf := bytes.NewBuffer(nil)
	err := s.Serialize(buf)
	if err != nil {
		return err
	}
	if s.IssuerKeyId == nil {
		return errors.New("Signature missing issuer key ID")
	}
	sig.Creation = s.CreationTime
	sig.Expiration = NeverExpires
	sig.Packet = buf.Bytes()
	sig.SigType = int(s.SigType)
	// Extract the issuer key id
	var issuerKeyId [8]byte
	binary.BigEndian.PutUint64(issuerKeyId[:], *s.IssuerKeyId)
	sigKeyId := hex.EncodeToString(issuerKeyId[:])
	sig.RIssuerKeyId = util.Reverse(sigKeyId)
	// Expiration time
	if s.SigLifetimeSecs != nil {
		sig.Expiration = s.CreationTime.Add(
			time.Duration(*s.SigLifetimeSecs) * time.Second)
	}
	return nil
}

func (sig *Signature) Visit(visitor PacketVisitor) (err error) {
	return visitor(sig)
}

type UserId struct {
	ScopedDigest  string         `db:"uuid"`        // immutable
	Creation      time.Time      `db:"creation"`    // mutable (derived from latest sigs)
	Expiration    time.Time      `db:"expiration"`  // mutable
	State         int            `db:"state"`       // mutable
	Packet        []byte         `db:"packet"`      // immutable
	PubkeyRFP     string         `db:"pubkey_uuid"` // immutable
	RevSigDigest  sql.NullString `db:"revsig_uuid"` // mutable
	Keywords      string         `db:"keywords"`    // immutable
	revSig        *Signature     `db:"-"`
	selfSignature *Signature     `db:"-"`
	signatures    []*Signature   `db:"-"`
}

func (uid *UserId) calcScopedDigest(pubkey *Pubkey) string {
	h := sha256.New()
	h.Write([]byte(pubkey.RFingerprint))
	h.Write(uid.Packet)
	return toAscii85String(h.Sum(nil))
}

func (uid *UserId) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(uid.Packet)
}

func (uid *UserId) GetPacket() (packet.Packet, error) {
	return uid.GetUserId()
}

func (uid *UserId) GetUserId() (*packet.UserId, error) {
	buf := bytes.NewBuffer(uid.Packet)
	u, err := packet.Read(buf)
	return u.(*packet.UserId), err
}

func (uid *UserId) SetPacket(p packet.Packet) error {
	u, is := p.(*packet.UserId)
	if !is {
		return ErrInvalidPacketType
	}
	return uid.SetUserId(u)
}

func (uid *UserId) SetUserId(u *packet.UserId) error {
	buf := bytes.NewBuffer(nil)
	err := u.Serialize(buf)
	if err != nil {
		return err
	}
	uid.Packet = buf.Bytes()
	uid.Creation = NeverExpires
	uid.Expiration = time.Unix(0, 0)
	uid.Keywords = util.CleanUtf8(u.Id)
	return nil
}

func (uid *UserId) Visit(visitor PacketVisitor) (err error) {
	err = visitor(uid)
	if err != nil {
		return
	}
	for _, sig := range uid.signatures {
		err = sig.Visit(visitor)
		if err != nil {
			return
		}
	}
	return
}

type UserAttribute struct {
	ScopedDigest  string         `db:"uuid"`        // immutable
	Creation      time.Time      `db:"creation"`    // mutable (derived from latest sigs)
	Expiration    time.Time      `db:"expiration"`  // mutable
	State         int            `db:"state"`       // mutable
	Packet        []byte         `db:"packet"`      // immutable
	PubkeyRFP     string         `db:"pubkey_uuid"` // immutable
	RevSigDigest  sql.NullString `db:"revsig_uuid"` // mutable
	revSig        *Signature     `db:"-"`
	selfSignature *Signature     `db:"-"`
	signatures    []*Signature   `db:"-"`
}

func (uat *UserAttribute) calcScopedDigest(pubkey *Pubkey) string {
	h := sha256.New()
	h.Write([]byte(pubkey.RFingerprint))
	h.Write(uat.Packet)
	return toAscii85String(h.Sum(nil))
}

func (uat *UserAttribute) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(uat.Packet)
}

func (uat *UserAttribute) GetPacket() (packet.Packet, error) {
	return uat.GetOpaquePacket()
}

func (uat *UserAttribute) SetPacket(p packet.Packet) error {
	op, is := p.(*packet.OpaquePacket)
	if !is {
		return ErrInvalidPacketType
	}
	return uat.SetOpaquePacket(op)
}

func (uat *UserAttribute) SetOpaquePacket(op *packet.OpaquePacket) error {
	buf := bytes.NewBuffer([]byte{})
	err := op.Serialize(buf)
	if err != nil {
		return err
	}
	uat.Packet = buf.Bytes()
	uat.Creation = NeverExpires
	uat.Expiration = time.Unix(0, 0)
	return nil
}

// Image subpacket type
const ImageSubType = 1

// Byte offset of image data in image subpacket
const ImageSubOffset = 16

// Get all images contained in UserAttribute packet
func (uat *UserAttribute) GetJpegData() (result []*bytes.Buffer) {
	op, err := uat.GetOpaquePacket()
	if err != nil {
		return
	}
	subpackets, err := packet.OpaqueSubpackets(op.Contents)
	if err != nil {
		return
	}
	for _, subpacket := range subpackets {
		if subpacket.SubType == ImageSubType && len(subpacket.Contents) > ImageSubOffset {
			result = append(result,
				bytes.NewBuffer(subpacket.Contents[ImageSubOffset:]))
		}
	}
	return result
}

func (uat *UserAttribute) Visit(visitor PacketVisitor) (err error) {
	err = visitor(uat)
	if err != nil {
		return
	}
	for _, sig := range uat.signatures {
		err = sig.Visit(visitor)
		if err != nil {
			return
		}
	}
	return
}

type Subkey struct {
	RFingerprint string         `db:"uuid"`        // immutable
	Creation     time.Time      `db:"creation"`    // immutable
	Expiration   time.Time      `db:"expiration"`  // mutable
	State        int            `db:"state"`       // mutable
	Packet       []byte         `db:"packet"`      // immutable
	PubkeyRFP    string         `db:"pubkey_uuid"` // immutable
	RevSigDigest sql.NullString `db:"revsig_uuid"` // mutable
	Algorithm    int            `db:"algorithm"`   // immutable
	BitLen       int            `db:"bit_len"`     // immutable
	signatures   []*Signature   `db:"-"`
	revSig       *Signature     `db:"-"`
	bindingSig   *Signature     `db:"-"`
}

func (subkey *Subkey) Fingerprint() string {
	return util.Reverse(subkey.RFingerprint)
}

func (subkey *Subkey) KeyId() string {
	return util.Reverse(subkey.RFingerprint[:16])
}

func (subkey *Subkey) ShortId() string {
	return util.Reverse(subkey.RFingerprint[:8])
}

func (subkey *Subkey) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(subkey.Packet)
}

func (subkey *Subkey) GetPacket() (packet.Packet, error) {
	return subkey.GetPublicKey()
}

func (subkey *Subkey) GetPublicKey() (*packet.PublicKey, error) {
	buf := bytes.NewBuffer(subkey.Packet)
	pk, err := packet.Read(buf)
	return pk.(*packet.PublicKey), err
}

func (subkey *Subkey) SetPacket(p packet.Packet) error {
	pk, is := p.(*packet.PublicKey)
	if !is {
		return ErrInvalidPacketType
	}
	return subkey.SetPublicKey(pk)
}

func (subkey *Subkey) SetPublicKey(pk *packet.PublicKey) error {
	buf := bytes.NewBuffer(nil)
	err := pk.Serialize(buf)
	if err != nil {
		return err
	}
	fingerprint := Fingerprint(pk)
	bitLen, err := pk.BitLength()
	if err != nil {
		return err
	}
	if !pk.IsSubkey {
		log.Println("Expected sub-key packet, got primary public key")
		return ErrInvalidPacketType
	}
	subkey.Packet = buf.Bytes()
	subkey.RFingerprint = util.Reverse(fingerprint)
	subkey.Creation = pk.CreationTime
	subkey.Expiration = NeverExpires
	subkey.Algorithm = int(pk.PubKeyAlgo)
	subkey.BitLen = int(bitLen)
	return nil
}

func (subkey *Subkey) Visit(visitor PacketVisitor) (err error) {
	err = visitor(subkey)
	if err != nil {
		return
	}
	for _, sig := range subkey.signatures {
		err = sig.Visit(visitor)
		if err != nil {
			return
		}
	}
	return
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

/* Appending signatures */

func (pubkey *Pubkey) AddSignature(sig *Signature) {
	pubkey.signatures = append(pubkey.signatures, sig)
}

func (uid *UserId) AddSignature(sig *Signature) {
	uid.signatures = append(uid.signatures, sig)
}

func (uat *UserAttribute) AddSignature(sig *Signature) {
	uat.signatures = append(uat.signatures, sig)
}

func (subkey *Subkey) AddSignature(sig *Signature) {
	subkey.signatures = append(subkey.signatures, sig)
}
