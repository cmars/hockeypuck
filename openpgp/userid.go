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
	"launchpad.net/hockeypuck/util"
	"strings"
	"time"
)

type UserId struct {
	ScopedDigest string         `db:"uuid"`        // immutable
	Creation     time.Time      `db:"creation"`    // mutable (derived from latest sigs)
	Expiration   time.Time      `db:"expiration"`  // mutable
	State        int            `db:"state"`       // mutable
	Packet       []byte         `db:"packet"`      // immutable
	PubkeyRFP    string         `db:"pubkey_uuid"` // immutable
	RevSigDigest sql.NullString `db:"revsig_uuid"` // mutable
	Keywords     string         `db:"keywords"`    // immutable

	/* Cross-references */

	revSig        *Signature   `db:"-"`
	selfSignature *Signature   `db:"-"`
	signatures    []*Signature `db:"-"`

	/* Parsed packet data */

	UserId *packet.UserId
}

func (uid *UserId) calcScopedDigest(pubkey *Pubkey) string {
	h := sha256.New()
	h.Write([]byte(pubkey.RFingerprint))
	h.Write([]byte("{uid}"))
	h.Write(uid.Packet)
	return toAscii85String(h.Sum(nil))
}

func (uid *UserId) Serialize(w io.Writer) error {
	_, err := w.Write(uid.Packet)
	return err
}

func (uid *UserId) Uuid() string { return uid.ScopedDigest }

func (uid *UserId) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(uid.Packet)
}

func (uid *UserId) GetPacket() (packet.Packet, error) {
	if uid.UserId != nil {
		return uid.UserId, nil
	}
	return nil, ErrPacketRecordState
}

func (uid *UserId) setPacket(p packet.Packet) error {
	u, is := p.(*packet.UserId)
	if !is {
		return ErrInvalidPacketType
	}
	uid.UserId = u
	return nil
}

func (uid *UserId) Read() (err error) {
	buf := bytes.NewBuffer(uid.Packet)
	var p packet.Packet
	if p, err = packet.Read(buf); err != nil {
		return
	}
	return uid.setPacket(p)
}

func NewUserId(p packet.Packet) (uid *UserId, err error) {
	uid = new(UserId)
	if err = uid.setPacket(p); err != nil {
		return
	}
	return uid, uid.init()
}

func (uid *UserId) init() (err error) {
	var buf bytes.Buffer
	if err = uid.UserId.Serialize(&buf); err != nil {
		return
	}
	uid.Packet = buf.Bytes()
	uid.Creation = NeverExpires
	uid.Expiration = time.Unix(0, 0)
	uid.Keywords = util.CleanUtf8(uid.UserId.Id)
	return
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

func (uid *UserId) AddSignature(sig *Signature) {
	uid.signatures = append(uid.signatures, sig)
}

func (uid *UserId) linkSelfSigs(pubkey *Pubkey) {
	for _, sig := range uid.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			continue
		}
		if sig.SigType == 0x30 { // TODO: add packet.SigTypeCertRevocation
			if uid.revSig == nil || sig.Creation.Unix() < uid.revSig.Creation.Unix() {
				if err := pubkey.verifyUserIdSelfSig(uid, sig); err == nil {
					uid.revSig = sig
					uid.RevSigDigest = sql.NullString{sig.ScopedDigest, true}
				}
			}
		}
	}
	if uid.revSig != nil {
		// Check for existing primary that was revoked.
		if pubkey.PrimaryUid.String == uid.ScopedDigest {
			pubkey.PrimaryUid = sql.NullString{"", false}
			pubkey.primaryUid = nil
			pubkey.primaryUidSig = nil
		}
		return
	}
	// Look for a better primary UID
	for _, sig := range uid.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			// Ignore signatures not made by this key (not self-sig)
			continue
		}
		if time.Now().Unix() > sig.Expiration.Unix() {
			// Ignore expired signatures
			continue
		}
		if sig.SigType >= 0x10 && sig.SigType <= 0x13 {
			if err := pubkey.verifyUserIdSelfSig(uid, sig); err == nil {
				if uid.selfSignature == nil || sig.Creation.Unix() > uid.selfSignature.Creation.Unix() {
					// Choose the most-recent self-signature on the uid
					uid.selfSignature = sig
				}
				var replace bool
				if pubkey.primaryUidSig == nil {
					// If we don't have a prior primary, let's start with this one
					replace = true
				} else if sig.Creation.Unix() > pubkey.primaryUidSig.Creation.Unix() {
					// If this uid signature is newer than the current primary candidate,
					// and its either signed as primary, or we haven't yet found a primary
					// uid, prefer this one.
					if sig.IsPrimary() || !pubkey.primaryUidSig.IsPrimary() {
						replace = true
					}
				}
				if replace {
					pubkey.primaryUid = uid
					pubkey.PrimaryUid = sql.NullString{uid.ScopedDigest, true}
					pubkey.primaryUidSig = sig
				}
			}
		}
	}
	// Remove User Ids without a self-signature
	if uid.selfSignature == nil {
		var userIds []*UserId
		for i := range pubkey.userIds {
			if pubkey.userIds[i] != uid {
				userIds = append(userIds, pubkey.userIds[i])
			}
		}
		pubkey.userIds = userIds
	}
}
