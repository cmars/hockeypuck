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
	"database/sql"
	"encoding/ascii85"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"code.google.com/p/go.crypto/openpgp/packet"

	"github.com/hockeypuck/hockeypuck/util"
)

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

	/* Containment references */

	PubkeyUuid sql.NullString `db:"pubkey_uuid"`
	SubkeyUuid sql.NullString `db:"subkey_uuid"`
	UidUuid    sql.NullString `db:"uid_uuid"`
	UatUuid    sql.NullString `db:"uat_uuid"`
	SigUuid    sql.NullString `db:"sig_uuid"`

	/* Cross-references */

	revSig *Signature

	/* Parsed packet data */

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
	h.Write([]byte("{sig}"))
	h.Write([]byte(scope))
	h.Write([]byte("{sig}"))
	h.Write(sig.Packet)
	return toAscii85String(h.Sum(nil))
}

func (sig *Signature) Serialize(w io.Writer) error {
	_, err := w.Write(sig.Packet)
	return err
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
		return err
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
		return nil, err
	}
	sig := &Signature{Packet: buf.Bytes()}
	p, err := op.Parse()
	if err != nil {
		return nil, err
	}
	if err = sig.setPacket(p); err != nil {
		return nil, err
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

func (sig *Signature) initV3() {
	sig.Creation = sig.SignatureV3.CreationTime
	// V3 packets do not have an expiration time
	sig.Expiration = NeverExpires
	sig.SigType = int(sig.SignatureV3.SigType)
	// Extract the issuer key id
	var issuerKeyId [8]byte
	binary.BigEndian.PutUint64(issuerKeyId[:], sig.SignatureV3.IssuerKeyId)
	sigKeyId := hex.EncodeToString(issuerKeyId[:])
	sig.RIssuerKeyId = util.Reverse(sigKeyId)
}

func (sig *Signature) initV4() error {
	if sig.Signature.IssuerKeyId == nil {
		return errors.New("Signature missing issuer key ID")
	}
	sig.Creation = sig.Signature.CreationTime
	sig.Expiration = NeverExpires
	sig.SigType = int(sig.Signature.SigType)
	// Extract the issuer key id
	var issuerKeyId [8]byte
	if sig.Signature.IssuerKeyId != nil {
		binary.BigEndian.PutUint64(issuerKeyId[:], *sig.Signature.IssuerKeyId)
		sigKeyId := hex.EncodeToString(issuerKeyId[:])
		sig.RIssuerKeyId = util.Reverse(sigKeyId)
	}
	// Expiration time
	if sig.Signature.SigLifetimeSecs != nil {
		sig.Expiration = sig.Signature.CreationTime.Add(
			time.Duration(*sig.Signature.SigLifetimeSecs) * time.Second)
	}
	return nil
}

func (sig *Signature) Visit(visitor PacketVisitor) error {
	return visitor(sig)
}

func (sig *Signature) IsPrimary() bool {
	return sig.Signature != nil && sig.Signature.IsPrimaryId != nil && *sig.Signature.IsPrimaryId
}
