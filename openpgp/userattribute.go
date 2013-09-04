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
	"io"
	"strings"
	"time"
)

type UserAttribute struct {
	ScopedDigest string         `db:"uuid"`        // immutable
	Creation     time.Time      `db:"creation"`    // mutable (derived from latest sigs)
	Expiration   time.Time      `db:"expiration"`  // mutable
	State        int            `db:"state"`       // mutable
	Packet       []byte         `db:"packet"`      // immutable
	PubkeyRFP    string         `db:"pubkey_uuid"` // immutable
	RevSigDigest sql.NullString `db:"revsig_uuid"` // mutable

	/* Cross-references */

	revSig        *Signature   `db:"-"`
	selfSignature *Signature   `db:"-"`
	signatures    []*Signature `db:"-"`

	/* Parsed packet data */

	UserAttribute *packet.UserAttribute
}

func (uat *UserAttribute) calcScopedDigest(pubkey *Pubkey) string {
	h := sha256.New()
	h.Write([]byte(pubkey.RFingerprint))
	h.Write(uat.Packet)
	return toAscii85String(h.Sum(nil))
}

func (uat *UserAttribute) Serialize(w io.Writer) error {
	_, err := w.Write(uat.Packet)
	return err
}

func (uat *UserAttribute) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(uat.Packet)
}

func (uat *UserAttribute) GetPacket() (packet.Packet, error) {
	if uat.UserAttribute != nil {
		return uat.UserAttribute, nil
	}
	return nil, ErrPacketRecordState
}

func (uat *UserAttribute) setPacket(p packet.Packet) error {
	u, is := p.(*packet.UserAttribute)
	if !is {
		return ErrInvalidPacketType
	}
	uat.UserAttribute = u
	return nil
}

func (uat *UserAttribute) Read() (err error) {
	buf := bytes.NewBuffer(uat.Packet)
	var p packet.Packet
	if p, err = packet.Read(buf); err != nil {
		return err
	}
	return uat.setPacket(p)
}

func NewUserAttribute(p packet.Packet) (uat *UserAttribute, err error) {
	uat = new(UserAttribute)
	if err = uat.setPacket(p); err != nil {
		return
	}
	return uat, uat.init()
}

func (uat *UserAttribute) init() (err error) {
	buf := bytes.NewBuffer(nil)
	if err = uat.UserAttribute.Serialize(buf); err != nil {
		return
	}
	uat.Packet = buf.Bytes()
	uat.Creation = NeverExpires
	uat.Expiration = time.Unix(0, 0)
	return
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

func (uat *UserAttribute) AddSignature(sig *Signature) {
	uat.signatures = append(uat.signatures, sig)
}

func (uat *UserAttribute) linkSelfSigs(pubkey *Pubkey) {
	for _, sig := range uat.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			continue
		}
		if sig.SigType == 0x30 { // TODO: add packet.SigTypeCertRevocation
			if uat.revSig == nil || sig.Creation.Unix() < uat.revSig.Creation.Unix() {
				if err := pubkey.verifyUserAttrSelfSig(uat, sig); err == nil {
					uat.revSig = sig
					uat.RevSigDigest = sql.NullString{sig.ScopedDigest, true}
				}
			}
		} else if sig.SigType >= 0x10 && sig.SigType <= 0x13 {
			if err := pubkey.verifyUserAttrSelfSig(uat, sig); err == nil {
				if uat.selfSignature == nil || sig.Creation.Unix() < uat.selfSignature.Creation.Unix() {
					uat.selfSignature = sig
				}
				if sig.Signature != nil && sig.Signature.IsPrimaryId != nil && *sig.Signature.IsPrimaryId {
					if (pubkey.primaryUatSig == nil || sig.Creation.Unix() < pubkey.primaryUatSig.Creation.Unix()) && time.Now().Unix() < sig.Expiration.Unix() {
						pubkey.primaryUat = uat
						pubkey.PrimaryUat = sql.NullString{uat.ScopedDigest, true}
						pubkey.primaryUatSig = sig
					}
				}
			}
		}
	}
	// Remove User Attributes without a self-signature
	if uat.selfSignature == nil {
		var userAttributes []*UserAttribute
		for i := range pubkey.userAttributes {
			if pubkey.userAttributes[i] != uat {
				userAttributes = append(userAttributes, pubkey.userAttributes[i])
			}
		}
		pubkey.userAttributes = userAttributes
	}
}
