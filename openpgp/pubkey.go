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
	"crypto"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"strings"
	"time"

	"code.google.com/p/go.crypto/openpgp/errors"
	"code.google.com/p/go.crypto/openpgp/packet"

	"github.com/hockeypuck/hockeypuck/util"
)

const (
	PubkeyStateOk      = 0
	PubkeyStateInvalid = iota
)

// Pubkey represents an OpenPGP public key packet.
// Searchable fields are extracted from the packet key material
// stored in Packet, for database indexing.
type Pubkey struct {

	/* Database fields */

	RFingerprint string         `db:"uuid"`        // immutable
	Creation     time.Time      `db:"creation"`    // immutable
	Expiration   time.Time      `db:"expiration"`  // mutable
	State        int            `db:"state"`       // mutable
	Packet       []byte         `db:"packet"`      // immutable
	Ctime        time.Time      `db:"ctime"`       // immutable
	Mtime        time.Time      `db:"mtime"`       // mutable
	Md5          string         `db:"md5"`         // mutable
	Sha256       string         `db:"sha256"`      // mutable
	RevSigDigest sql.NullString `db:"revsig_uuid"` // mutable
	PrimaryUid   sql.NullString `db:"primary_uid"` // mutable
	PrimaryUat   sql.NullString `db:"primary_uat"` // mutable
	Algorithm    int            `db:"algorithm"`   // immutable
	BitLen       int            `db:"bit_len"`     // immutable
	Unsupported  []byte         `db:"unsupp"`      // mutable

	/* Containment references */

	signatures     []*Signature     `db:"-"`
	subkeys        []*Subkey        `db:"-"`
	userIds        []*UserId        `db:"-"`
	userAttributes []*UserAttribute `db:"-"`

	/* Cross-references */

	revSig        *Signature     `db:"-"`
	primaryUid    *UserId        `db:"-"`
	primaryUidSig *Signature     `db:"-"`
	primaryUat    *UserAttribute `db:"-"`
	primaryUatSig *Signature     `db:"-"`

	/* Parsed packet data */

	PublicKey   *packet.PublicKey
	PublicKeyV3 *packet.PublicKeyV3
}

func (pubkey *Pubkey) Fingerprint() string {
	return util.Reverse(pubkey.RFingerprint)
}

func (pubkey *Pubkey) KeyId() string {
	if pubkey.PublicKeyV3 != nil {
		return fmt.Sprintf("%016x", pubkey.PublicKeyV3.KeyId)
	}
	return util.Reverse(pubkey.RFingerprint[:16])
}

func (pubkey *Pubkey) ShortId() string {
	if pubkey.PublicKeyV3 != nil {
		return fmt.Sprintf("%08x", uint32(pubkey.PublicKeyV3.KeyId))
	}
	return util.Reverse(pubkey.RFingerprint[:8])
}

func (pubkey *Pubkey) UserIds() []*UserId { return pubkey.userIds }

func (pubkey *Pubkey) UserAttributes() []*UserAttribute { return pubkey.userAttributes }

func (pubkey *Pubkey) Subkeys() []*Subkey { return pubkey.subkeys }

func (pubkey *Pubkey) Serialize(w io.Writer) error {
	_, err := w.Write(pubkey.Packet)
	return err
}

func (pubkey *Pubkey) Uuid() string { return pubkey.RFingerprint }

func (pubkey *Pubkey) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(pubkey.Packet)
}

func (pubkey *Pubkey) GetPacket() (packet.Packet, error) {
	var p packet.Packet
	if pubkey.PublicKey != nil {
		p = pubkey.PublicKey
	} else if pubkey.PublicKeyV3 != nil {
		p = pubkey.PublicKeyV3
	} else {
		return nil, ErrPacketRecordState
	}
	return p, nil
}

func (pubkey *Pubkey) setPacket(p packet.Packet) error {
	switch pk := p.(type) {
	case *packet.PublicKey:
		if pk.IsSubkey {
			return ErrInvalidPacketType
		}
		pubkey.PublicKey = pk
	case *packet.PublicKeyV3:
		if pk.IsSubkey {
			return ErrInvalidPacketType
		}
		pubkey.PublicKeyV3 = pk
	default:
		return ErrInvalidPacketType
	}
	return nil
}

func (pubkey *Pubkey) Read() error {
	buf := bytes.NewBuffer(pubkey.Packet)
	p, err := packet.Read(buf)
	if err != nil {
		if pubkey.State&PacketStateUnsuppPubkey != 0 {
			return nil
		}
		return err
	}
	return pubkey.setPacket(p)
}

func (pubkey *Pubkey) UnsupportedPackets() []*packet.OpaquePacket {
	var result []*packet.OpaquePacket
	r := packet.NewOpaqueReader(bytes.NewBuffer(pubkey.Unsupported))
	for op, err := r.Next(); err == nil; op, err = r.Next() {
		result = append(result, op)
	}
	return result
}

func NewPubkey(op *packet.OpaquePacket) (pubkey *Pubkey, _ error) {
	var buf bytes.Buffer
	var err error
	if err = op.Serialize(&buf); err != nil {
		panic("unable to write internal buffer")
	}
	pubkey = &Pubkey{Packet: buf.Bytes()}
	defer func() {
		if err != nil {
			pubkey.PublicKey = nil
			pubkey.PublicKeyV3 = nil
			// TODO: record the reason that the public key is unsupported
			// somewhere.
			pubkey.initUnsupported(op)
		}
	}()
	p, err := op.Parse()
	if err != nil {
		return pubkey, err
	}
	if err = pubkey.setPacket(p); err != nil {
		return pubkey, err
	}
	if pubkey.PublicKey != nil {
		err = pubkey.initV4()
	} else if pubkey.PublicKeyV3 != nil {
		err = pubkey.initV3()
	} else {
		err = ErrInvalidPacketType
	}
	return pubkey, nil
}

func (pubkey *Pubkey) initUnsupported(op *packet.OpaquePacket) {
	pubkey.State = PacketStateUnsuppPubkey
	// Calculate opaque fingerprint on unsupported public key packet
	h := sha1.New()
	h.Write([]byte{0x99, byte(len(op.Contents) >> 8), byte(len(op.Contents))})
	h.Write(op.Contents)
	fpr := hex.EncodeToString(h.Sum(nil))
	pubkey.RFingerprint = util.Reverse(fpr)
}

func (pubkey *Pubkey) initV4() error {
	buf := bytes.NewBuffer(nil)
	err := pubkey.PublicKey.Serialize(buf)
	if err != nil {
		return err
	}
	fingerprint := Fingerprint(pubkey.PublicKey)
	bitLen, err := pubkey.PublicKey.BitLength()
	if err != nil {
		return err
	}
	if pubkey.PublicKey.IsSubkey {
		log.Println("Expected primary public key packet, got sub-key")
		return ErrInvalidPacketType
	}
	pubkey.RFingerprint = util.Reverse(fingerprint)
	pubkey.Creation = pubkey.PublicKey.CreationTime
	pubkey.Expiration = NeverExpires
	pubkey.Algorithm = int(pubkey.PublicKey.PubKeyAlgo)
	pubkey.BitLen = int(bitLen)
	return nil
}

func (pubkey *Pubkey) initV3() error {
	var buf bytes.Buffer
	err := pubkey.PublicKeyV3.Serialize(&buf)
	if err != nil {
		return err
	}
	fingerprint := FingerprintV3(pubkey.PublicKeyV3)
	bitLen, err := pubkey.PublicKeyV3.BitLength()
	if err != nil {
		return err
	}
	if pubkey.PublicKeyV3.IsSubkey {
		log.Println("Expected primary public key packet, got sub-key")
		return ErrInvalidPacketType
	}
	pubkey.RFingerprint = util.Reverse(fingerprint)
	pubkey.Creation = pubkey.PublicKeyV3.CreationTime
	pubkey.Expiration = NeverExpires
	if pubkey.PublicKeyV3.DaysToExpire > 0 {
		pubkey.Expiration = pubkey.Creation.Add(time.Duration(pubkey.PublicKeyV3.DaysToExpire) * time.Hour * 24)
	}
	pubkey.Algorithm = int(pubkey.PublicKeyV3.PubKeyAlgo)
	pubkey.BitLen = int(bitLen)
	return nil
}

func (pubkey *Pubkey) Visit(visitor PacketVisitor) error {
	err := visitor(pubkey)
	if err != nil {
		return err
	}
	for _, sig := range pubkey.signatures {
		err = sig.Visit(visitor)
		if err != nil {
			return err
		}
	}
	for _, uid := range pubkey.userIds {
		err = uid.Visit(visitor)
		if err != nil {
			return err
		}
	}
	for _, uat := range pubkey.userAttributes {
		err = uat.Visit(visitor)
		if err != nil {
			return err
		}
	}
	for _, subkey := range pubkey.subkeys {
		err = subkey.Visit(visitor)
		if err != nil {
			return err
		}
	}
	return nil
}

func (pubkey *Pubkey) AddSignature(sig *Signature) {
	pubkey.signatures = append(pubkey.signatures, sig)
}

func (pubkey *Pubkey) RemoveSignature(sig *Signature) {
	pubkey.signatures = removeSignature(pubkey.signatures, sig)
}

func (pubkey *Pubkey) linkSelfSigs() {
	for _, sig := range pubkey.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			continue
		}
		if sig.SigType == 0x20 { // TODO: add packet.SigTypeKeyRevocation
			// Use the earliest valid revocation of this key
			if pubkey.revSig == nil || sig.Creation.Unix() < pubkey.revSig.Creation.Unix() {
				if err := pubkey.verifyPublicKeySelfSig(pubkey, sig); err == nil {
					pubkey.revSig = sig
				}
			}
		}
	}
}

func (pubkey *Pubkey) publicKey() *packet.PublicKey     { return pubkey.PublicKey }
func (pubkey *Pubkey) publicKeyV3() *packet.PublicKeyV3 { return pubkey.PublicKeyV3 }

func (pubkey *Pubkey) verifyPublicKeySelfSig(keyrec publicKeyRecord, sig *Signature) error {
	if !Config().VerifySigs() {
		return nil
	}
	if pubkey.PublicKey != nil && keyrec.publicKey() != nil {
		if sig.Signature != nil {
			err := pubkey.PublicKey.VerifyKeySignature(keyrec.publicKey(), sig.Signature)
			if err == nil {
				sig.State |= PacketStateSigOk
			}
			return err
		} else {
			return ErrInvalidPacketType
		}
	} else if pubkey.PublicKeyV3 != nil && keyrec.publicKeyV3() != nil {
		if sig.SignatureV3 != nil {
			err := pubkey.PublicKeyV3.VerifyKeySignatureV3(keyrec.publicKeyV3(), sig.SignatureV3)
			if err == nil {
				sig.State |= PacketStateSigOk
			}
			return err
		} else {
			return ErrInvalidPacketType
		}
	}
	return ErrPacketRecordState
}

func (pubkey *Pubkey) verifyUserIdSelfSig(uid *UserId, sig *Signature) error {
	if !Config().VerifySigs() {
		return nil
	}
	if uid.UserId == nil {
		return ErrPacketRecordState
	}
	if pubkey.PublicKey != nil {
		if sig.Signature != nil {
			err := pubkey.PublicKey.VerifyUserIdSignature(uid.UserId.Id, pubkey.PublicKey, sig.Signature)
			if err == nil {
				sig.State |= PacketStateSigOk
			}
			return err
		} else if sig.SignatureV3 != nil {
			err := pubkey.PublicKey.VerifyUserIdSignatureV3(uid.UserId.Id, pubkey.PublicKey, sig.SignatureV3)
			if err == nil {
				sig.State |= PacketStateSigOk
			}
			return err
		} else {
			return ErrInvalidPacketType
		}
	} else if pubkey.PublicKeyV3 != nil {
		if sig.SignatureV3 != nil {
			return pubkey.PublicKeyV3.VerifyUserIdSignatureV3(uid.UserId.Id, pubkey.PublicKeyV3, sig.SignatureV3)
		} else {
			return ErrInvalidPacketType
		}
	}
	return ErrPacketRecordState
}

func (pubkey *Pubkey) verifyUserAttrSelfSig(uat *UserAttribute, sig *Signature) error {
	if !Config().VerifySigs() {
		return nil
	}
	if uat.UserAttribute == nil {
		return ErrPacketRecordState
	}
	// Not sure if photo IDs are supported pre-V4. We'll just flag these as unvalidated
	// if they do happen to exist.
	if pubkey.PublicKey == nil {
		return ErrInvalidPacketType
	}
	if sig.Signature != nil {
		h, err := pubkey.sigSerializeUserAttribute(uat, sig.Signature.Hash)
		if err != nil {
			return err
		}
		return pubkey.PublicKey.VerifySignature(h, sig.Signature)
	}
	return ErrPacketRecordState
}

// sigSerializeUserAttribute calculates the user attribute packet hash
// TODO: clean up & contribute this to go.crypto/openpgp
func (pubkey *Pubkey) sigSerializeUserAttribute(uat *UserAttribute, hashFunc crypto.Hash) (hash.Hash, error) {
	if !hashFunc.Available() {
		return nil, errors.UnsupportedError("hash function")
	}
	h := hashFunc.New()

	// Get user attribute opaque packet
	uatOpaque, err := uat.GetOpaquePacket()
	if err != nil {
		return nil, err
	}
	// Get public key opaque packet.
	pkOpaque, err := pubkey.GetOpaquePacket()
	if err != nil {
		return nil, err
	}
	// RFC 4880, section 5.2.4
	// Write the signature prefix and public key contents to hash
	pubkey.PublicKey.SerializeSignaturePrefix(h)
	h.Write(pkOpaque.Contents)
	// V4 certification hash
	var buf [5]byte
	// User attribute constant
	buf[0] = 0xd1
	// Big-endian length of user attribute contents
	l := len(uatOpaque.Contents)
	buf[1] = byte(l >> 24)
	buf[2] = byte(l >> 16)
	buf[3] = byte(l >> 8)
	buf[4] = byte(l)
	h.Write(buf[:])
	// User attribute contents
	h.Write(uatOpaque.Contents)
	return h, nil
}

func (pubkey *Pubkey) AppendUnsupported(opkt *packet.OpaquePacket) {
	var buf bytes.Buffer
	opkt.Serialize(&buf)
	pubkey.Unsupported = append(pubkey.Unsupported, buf.Bytes()...)
}
