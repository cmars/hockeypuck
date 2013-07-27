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
	"encoding/binary"
	"errors"
)

var ErrNoSelfSignature error = errors.New("Self-signature not found")
var ErrNoBindingSignature error = errors.New("Binding signature not found")

// BadPacket associates an error with a packet record.
type BadPacket struct {
	Record PacketRecord
	Reason error
}

// BadPacketMap indexes packet integrity problems by the packet record's
// unique identifier.
type BadPacketMap map[string]*BadPacket

// KeyValidation represents the result of checking the integrity
// of a public key record. The public key material may be repaired
// and invalid content removed as a side-effect of the validation
// process.
type KeyValidation struct {
	Pubkey     *Pubkey
	publicKey  *packet.PublicKey
	Changed    bool
	BadPackets BadPacketMap
	KeyError   error
}

// ValidateKey checks the integrity of OpenPGP packets and signatures
// in a public key record. Unauthenticated and invalid content is
// flagged and removed where possible.
func ValidateKey(pubkey *Pubkey) *KeyValidation {
	kv := &KeyValidation{Pubkey: pubkey, BadPackets: make(BadPacketMap)}
	pubkey.Visit(kv.resolve)
	pubkey.Visit(kv.validate)
	kv.removeInvalid()
	return kv
}

// bad marks a bad packet to be disregarded and discarded.
func (kv *KeyValidation) bad(rec PacketRecord, err error) {
	bp := &BadPacket{rec, err}
	switch r := rec.(type) {
	case *Pubkey:
		kv.BadPackets[r.RFingerprint] = bp
	case *Signature:
		kv.BadPackets[r.ScopedDigest] = bp
	case *UserId:
		kv.BadPackets[r.ScopedDigest] = bp
	case *UserAttribute:
		kv.BadPackets[r.ScopedDigest] = bp
	case *Subkey:
		kv.BadPackets[r.RFingerprint] = bp
	}
}

// removeInvalid prunes the public key record structure of
// any invalid packets.
func (kv *KeyValidation) removeInvalid() {
	kv.removeInvalidUids()
	kv.removeInvalidUats()
	kv.removeInvalidSubkeys()
	// Set KeyError based on whether the pruned key material
	// contains some proof that the private key made a signature on *something*.
	if len(kv.Pubkey.subkeys) == 0 && len(kv.Pubkey.userIds) == 0 &&
		len(kv.Pubkey.userAttributes) == 0 && kv.Pubkey.revSig == nil {
		// There's nothing self-signed left in this public key packet!
		kv.KeyError = ErrNoSelfSignature
	}
}

func (kv *KeyValidation) removeInvalidUids() {
	var userIds []*UserId
	var uidChanged bool
	for _, uid := range kv.Pubkey.userIds {
		if _, has := kv.BadPackets[uid.ScopedDigest]; !has {
			userIds = append(userIds, uid)
		} else {
			uidChanged = true
		}
		uid.signatures = kv.removeInvalidSigs(uid.signatures)
	}
	if uidChanged {
		kv.Changed = true
		kv.Pubkey.userIds = userIds
	}
}

func (kv *KeyValidation) removeInvalidUats() {
	var userAttributes []*UserAttribute
	var uatChanged bool
	for _, uat := range kv.Pubkey.userAttributes {
		if _, has := kv.BadPackets[uat.ScopedDigest]; !has {
			userAttributes = append(userAttributes, uat)
		} else {
			uatChanged = true
		}
		uat.signatures = kv.removeInvalidSigs(uat.signatures)
	}
	if uatChanged {
		kv.Changed = true
		kv.Pubkey.userAttributes = userAttributes
	}
}

func (kv *KeyValidation) removeInvalidSubkeys() {
	var subkeys []*Subkey
	var subkeyChanged bool
	for _, subkey := range kv.Pubkey.subkeys {
		if _, has := kv.BadPackets[subkey.RFingerprint]; !has {
			subkeys = append(subkeys, subkey)
		} else {
			subkeyChanged = true
		}
		subkey.signatures = kv.removeInvalidSigs(subkey.signatures)
	}
	if subkeyChanged {
		kv.Changed = true
		kv.Pubkey.subkeys = subkeys
	}
}

func (kv *KeyValidation) removeInvalidSigs(allSigs []*Signature) []*Signature {
	var goodSigs []*Signature
	var sigChanged bool
	for _, sig := range allSigs {
		if _, has := kv.BadPackets[sig.ScopedDigest]; !has {
			goodSigs = append(goodSigs, sig)
		} else {
			sigChanged = true
		}
	}
	if sigChanged {
		kv.Changed = true
		return goodSigs
	}
	return allSigs
}

// validate checks the overall structure of the Hockeypuck
// public key model, making fixes where possible.
// Records lacking self-signatures are removed, and the database
// foreign key reference fields are updated according to the packet
// relationships discovered in the resolve phase.
// Returns an error to indicate the overall fitness of the key material
// after repair.
func (kv *KeyValidation) validate(rec PacketRecord) (err error) {
	switch r := rec.(type) {
	case *Pubkey:
		var revsig string
		if r.revSig != nil {
			revsig = r.revSig.ScopedDigest
		}
		if revsig != r.RevSigDigest {
			r.RevSigDigest = revsig
			kv.Changed = true
		}
		var primaryUid string
		if r.primaryUid != nil {
			primaryUid = r.primaryUid.ScopedDigest
		}
		if primaryUid != r.PrimaryUid {
			r.PrimaryUid = primaryUid
			kv.Changed = true
		}
		var primaryUat string
		if r.primaryUat != nil {
			primaryUat = r.primaryUat.ScopedDigest
		}
		if primaryUat != r.PrimaryUat {
			r.PrimaryUat = primaryUat
			kv.Changed = true
		}
	case *UserId:
		var revsig string
		if r.revSig != nil {
			revsig = r.revSig.ScopedDigest
		}
		if revsig != r.RevSigDigest {
			r.RevSigDigest = revsig
			kv.Changed = true
		}
	case *UserAttribute:
		var revsig string
		if r.revSig != nil {
			revsig = r.revSig.ScopedDigest
		}
		if revsig != r.RevSigDigest {
			r.RevSigDigest = revsig
			kv.Changed = true
		}
	case *Subkey:
		var revsig string
		if r.revSig != nil {
			revsig = r.revSig.ScopedDigest
		}
		if revsig != r.RevSigDigest {
			r.RevSigDigest = revsig
			kv.Changed = true
		}
	}
	return
}

// resolve builds packet signature associations such as self-signatures,
// primary UID and user attribute flags, and revocations. It also "pings"
// each packet to make sure it parses, and fixes inconsistencies with the
// Hockeypuck record representation.
func (kv *KeyValidation) resolve(rec PacketRecord) (err error) {
	switch r := rec.(type) {
	case *Pubkey:
		err = kv.resolvePubkey(r)
	case *UserId:
		err = kv.resolveUserId(r)
	case *UserAttribute:
		err = kv.resolveUserAttribute(r)
	case *Subkey:
		err = kv.resolveSubkey(r)
	}
	return
}

// HasKeyidSuffix returns true if the keyid matches the full fingerprint.
func HasKeyidSuffix(fingerprint []byte, keyid uint64) bool {
	keyidBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(keyidBuf, keyid)
	return bytes.HasSuffix(fingerprint, keyidBuf)
}

func (kv *KeyValidation) resolvePubkey(pubkey *Pubkey) error {
	var err error
	kv.publicKey, err = pubkey.GetPublicKey()
	if err != nil {
		// Can't even parse a public key packet, too bad
		kv.bad(pubkey, err)
		return err
	}
	// Check key revocations
	for _, sig := range pubkey.signatures {
		kv.getFixedSigScope(sig, pubkey.RFingerprint)
		s, err := sig.getSignatureV4()
		if err != nil {
			kv.bad(sig, err)
			continue
		}
		if HasKeyidSuffix(kv.publicKey.Fingerprint[:], *s.IssuerKeyId) {
			// This is a self-signature.
			switch s.SigType {
			case 0x20: // SigTypeKeyRevocation
				if err = kv.publicKey.VerifyKeySignature(kv.publicKey, s); err != nil {
					kv.bad(sig, err)
				}
				kv.Pubkey.revSig = sig
			}
		}
	}
	// TODO: Fix record fields from packet
	return nil
}

func (kv *KeyValidation) resolveSubkey(subkey *Subkey) error {
	subPublicKey, err := subkey.GetPublicKey()
	if err != nil {
		kv.bad(subkey, err)
		return nil
	}
	// Check key revocations
	for _, sig := range subkey.signatures {
		kv.getFixedSigScope(sig, subkey.RFingerprint)
		s, err := sig.getSignatureV4()
		if err != nil {
			kv.bad(sig, err)
			continue
		}
		if HasKeyidSuffix(kv.publicKey.Fingerprint[:], *s.IssuerKeyId) {
			// This is a self-signature.
			switch s.SigType {
			case 0x18:
				if err = kv.publicKey.VerifyKeySignature(subPublicKey, s); err != nil {
					kv.bad(sig, err)
					continue
				}
				subkey.bindingSig = sig
			// TODO: case 0x19: // Subkey cross-signature
			case 0x20: // SigTypeKeyRevocation
				if err = kv.publicKey.VerifyKeySignature(subPublicKey, s); err != nil {
					kv.bad(sig, err)
					continue
				}
				subkey.revSig = sig
			}
		}
	}
	if subkey.bindingSig == nil {
		kv.bad(subkey, ErrNoBindingSignature)
	}
	// TODO: Fix record fields from packet
	return nil
}

func (kv *KeyValidation) getFixedSigScope(sig *Signature, scope string) string {
	sigScope := sig.calcScopedDigest(kv.Pubkey, scope)
	if sigScope != sig.ScopedDigest {
		sig.ScopedDigest = sigScope
		kv.Changed = true
	}
	return sigScope
}

func (kv *KeyValidation) getFixedUidScope(uid *UserId) string {
	uidScope := uid.calcScopedDigest(kv.Pubkey)
	if uidScope != uid.ScopedDigest {
		uid.ScopedDigest = uidScope
		kv.Changed = true
	}
	return uidScope
}

func (kv *KeyValidation) getFixedUatScope(uat *UserAttribute) string {
	uatScope := uat.calcScopedDigest(kv.Pubkey)
	if uatScope != uat.ScopedDigest {
		uat.ScopedDigest = uatScope
		kv.Changed = true
	}
	return uatScope
}

func (kv *KeyValidation) resolveUserId(uid *UserId) error {
	u, err := uid.GetUserId()
	if err != nil {
		kv.bad(uid, err)
		return nil
	}
	uidScope := kv.getFixedUidScope(uid)
	// TODO: Fix record fields from packet
	for _, sig := range uid.signatures {
		kv.getFixedSigScope(sig, uidScope)
		s, err := sig.getSignatureV4()
		if err != nil {
			kv.bad(sig, err)
			continue
		}
		if HasKeyidSuffix(kv.publicKey.Fingerprint[:], *s.IssuerKeyId) {
			// This is a self-signature.
			// Expired and revoked is OK here. The purpose of this validation
			// is to verify the user ID was signed by the public key -- to
			// eliminate garbage, spoofing, etc.
			switch s.SigType {
			case packet.SigTypePositiveCert:
				if err = kv.publicKey.VerifyUserIdSignature(u.Id, s); err != nil {
					kv.bad(sig, err)
				}
				// Updating selfSignature multiple times is ok. We just want to be
				// sure this user ID was signed by the primary key at some point in time.
				uid.selfSignature = sig
				// Track the primary user ID for the key
				// TODO: need to reconcile and update the database FK after validation
				// if changed.
				if kv.Pubkey.primaryUid == nil || kv.Pubkey.primaryUidSig == nil {
					kv.Pubkey.primaryUid = uid
					kv.Pubkey.primaryUidSig = sig
				} else if s.IsPrimaryId != nil && *s.IsPrimaryId && (kv.Pubkey.primaryUidSig.Creation.Unix() < sig.Creation.Unix()) {
					kv.Pubkey.primaryUid = uid
					kv.Pubkey.primaryUidSig = sig
				}
			case 0x30: // packet.SigTypeCertRevocation
				// Detect and link user ID revocations
				if err = kv.publicKey.VerifyUserIdSignature(u.Id, s); err != nil {
					kv.bad(sig, err)
				} else {
					uid.revSig = sig
				}
			}
		}
	}
	if uid.selfSignature == nil {
		kv.bad(uid, ErrNoSelfSignature)
	}
	return nil
}

func (kv *KeyValidation) resolveUserAttribute(uat *UserAttribute) error {
	uatScope := kv.getFixedUatScope(uat)
	// TODO: Fix record fields from packet
	for _, sig := range uat.signatures {
		kv.getFixedSigScope(sig, uatScope)
		s, err := sig.getSignatureV4()
		if err != nil {
			kv.bad(sig, err)
			continue
		}
		if HasKeyidSuffix(kv.publicKey.Fingerprint[:], *s.IssuerKeyId) {
			// This is a self-signature.
			// Expired and revoked is OK here. The purpose of this validation
			// is to verify the user attr was signed by the public key -- to
			// eliminate garbage, spoofing, etc.
			switch s.SigType {
			case packet.SigTypePositiveCert:
				if err = kv.verifyUatSig(uat, s); err != nil {
					kv.bad(sig, err)
				}
				// Updating selfSignature multiple times is ok. We just want to be
				// sure this user attr was signed by the primary key at some point in time.
				uat.selfSignature = sig
				// Track the primary user attr for the key
				// TODO: need to reconcile and update the database FK after validation
				// if changed.
				if kv.Pubkey.primaryUat == nil || kv.Pubkey.primaryUatSig == nil {
					kv.Pubkey.primaryUat = uat
					kv.Pubkey.primaryUatSig = sig
				} else if s.IsPrimaryId != nil && *s.IsPrimaryId && (kv.Pubkey.primaryUatSig.Creation.Unix() < sig.Creation.Unix()) {
					kv.Pubkey.primaryUat = uat
					kv.Pubkey.primaryUatSig = sig
				}
			case 0x30: // packet.SigTypeCertRevocation
				// Detect and link user attr revocations
				if err = kv.verifyUatSig(uat, s); err != nil {
					kv.bad(sig, err)
				} else {
					uat.revSig = sig
				}
			}
		} else {
			// This is a signature made by someone else
			// TODO: look up public key and verify?
		}
	}
	if uat.selfSignature == nil {
		kv.bad(uat, ErrNoSelfSignature)
	}
	return nil
}

func (kv *KeyValidation) verifyUatSig(uat *UserAttribute, s *packet.Signature) error {
	// TODO: clean up & contribute this to go.crypto/openpgp
	// Get user attribute opaque packet
	uatOpaque, err := uat.GetOpaquePacket()
	if err != nil {
		return err
	}
	// Get public key opaque packet.
	pkOpaque, err := kv.Pubkey.GetOpaquePacket()
	if err != nil {
		return err
	}
	// Build up the hash for the signature
	h := s.Hash.New()
	// RFC 4880, section 5.2.4
	// Write the signature prefix and public key contents to hash
	kv.publicKey.SerializeSignaturePrefix(h)
	h.Write(pkOpaque.Contents) // equivalent to pk.serializeWithoutHeaders(h)
	// V4 certification hash
	var buf [5]byte
	// User attribute constant
	buf[0] = 0xd1
	// Big-endian length of user attribute contents
	buf[1] = byte(len(uatOpaque.Contents) >> 24)
	buf[2] = byte(len(uatOpaque.Contents) >> 16)
	buf[3] = byte(len(uatOpaque.Contents) >> 8)
	buf[4] = byte(len(uatOpaque.Contents))
	h.Write(buf[:])
	// User attribute contents
	h.Write(uatOpaque.Contents)
	return kv.publicKey.VerifySignature(h, s)
}
