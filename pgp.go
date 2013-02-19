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

package hockeypuck

import (
	"bytes"
	_ "code.google.com/p/go.crypto/md4"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/errors"
	"code.google.com/p/go.crypto/openpgp/packet"
	_ "code.google.com/p/go.crypto/ripemd160"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	Errors "errors"
	"fmt"
	"io"
	"log"
	"time"
)

// Comparable time flag for "never expires"
const NeverExpires = int64((1 << 63) - 1)

// Get the public key fingerprint as a hex string.
func Fingerprint(pubkey *packet.PublicKey) string {
	return hex.EncodeToString(pubkey.Fingerprint[:])
}

// Calculate a strong cryptographic digest used for
// fingerprinting key material and other user data.
func Digest(data []byte) string {
	h := sha512.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Write a public key as ASCII armored text.
func WriteKey(out io.Writer, key *PubKey) error {
	w, err := armor.Encode(out, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	defer w.Close()
	pktObjChan := make(chan PacketObject)
	defer FinishTraversal(pktObjChan)
	go func() {
		key.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	for pktObj := range pktObjChan {
		_, err = w.Write(pktObj.GetPacket())
		if err != nil {
			return err
		}
	}
	return nil
}

// Read one or more public keys from input.
func ReadKeys(r io.Reader) (keyChan chan *PubKey, errorChan chan error) {
	keyChan = make(chan *PubKey)
	errorChan = make(chan error)
	go func() {
		defer close(keyChan)
		defer close(errorChan)
		var err error
		var parseErr error
		var currentSignable Signable
		var currentUserId *UserId
		or := packet.NewOpaqueReader(r)
		var p packet.Packet
		var op *packet.OpaquePacket
		var pubKey *PubKey
		var fp string
		for op, err = or.Next(); err != io.EOF; op, err = or.Next() {
			if err != nil {
				errorChan <- err
				return
			}
			p, parseErr = op.Parse()
			switch p.(type) {
			case *packet.PublicKey:
				pk := p.(*packet.PublicKey)
				if !pk.IsSubkey && pubKey != nil {
					// New public key found, send prior one
					keyChan <- pubKey
					pubKey = nil
				}
				fp = Fingerprint(pk)
				keyLength, err := pk.BitLength()
				if err != nil {
					log.Println("Failed to read bit length, fingerprint:", fp)
					errorChan <- err
					continue
				}
				if !pk.IsSubkey {
					// This is the primary public key
					pubKey = &PubKey{
						RFingerprint: Reverse(fp),
						Algorithm:    int(pk.PubKeyAlgo),
						KeyLength:    keyLength}
					pubKey.SetPacket(op)
					currentSignable = pubKey
				} else {
					if pubKey == nil {
						continue
					}
					// This is a sub key
					subKey := &SubKey{
						RFingerprint: Reverse(fp),
						Algorithm:    int(pk.PubKeyAlgo),
						KeyLength:    keyLength}
					subKey.SetPacket(op)
					pubKey.SubKeys = append(pubKey.SubKeys, subKey)
					currentSignable = subKey
					currentUserId = nil
				}
			case *packet.Signature:
				if currentSignable == nil {
					continue
				}
				s := p.(*packet.Signature)
				// Read issuer key id.
				if s.IssuerKeyId == nil {
					// Without an issuer, a signature doesn't mean much
					log.Println("Signature missing IssuerKeyId!", "Public key fingerprint:",
						pubKey.Fingerprint())
					continue
				}
				var issuerKeyId [8]byte
				binary.BigEndian.PutUint64(issuerKeyId[:], *s.IssuerKeyId)
				sigExpirationTime := NeverExpires
				keyExpirationTime := NeverExpires
				// Expiration time
				if s.SigLifetimeSecs != nil {
					sigExpirationTime = s.CreationTime.Add(
						time.Duration(*s.SigLifetimeSecs) * time.Second).Unix()
				} else if s.KeyLifetimeSecs != nil {
					keyExpirationTime = s.CreationTime.Add(
						time.Duration(*s.KeyLifetimeSecs) * time.Second).Unix()
				}
				sigKeyId := hex.EncodeToString(issuerKeyId[:])
				sig := &Signature{
					SigType:           int(s.SigType),
					RIssuerKeyId:      Reverse(sigKeyId),
					CreationTime:      s.CreationTime.Unix(),
					SigExpirationTime: sigExpirationTime,
					KeyExpirationTime: keyExpirationTime}
				sig.SetPacket(op)
				currentSignable.AppendSig(sig)
			case *packet.UserId:
				if pubKey == nil {
					continue
				}
				uid := p.(*packet.UserId)
				id := CleanUtf8(uid.Id)
				userId := &UserId{
					Id:       id,
					Keywords: SplitUserId(id)}
				userId.SetPacket(op)
				currentSignable = userId
				currentUserId = userId
				pubKey.Identities = append(pubKey.Identities, userId)
			default:
				_, isUnknown := parseErr.(errors.UnknownPacketTypeError)
				if isUnknown {
					// Packets not yet supported by go.crypto/openpgp
					switch op.Tag {
					case 17: // Process user attribute packet
						userAttr := &UserAttribute{}
						userAttr.SetPacket(op)
						if currentUserId != nil {
							currentUserId.Attributes = append(currentUserId.Attributes, userAttr)
						}
						currentSignable = userAttr
					case 2: // Bad signature packet
						// TODO: Check for signature version 3
						log.Println(parseErr)
					case 6: // Bad public key packet
						// TODO: Check for unsupported PGP public key packet version
						// For now, clear state, ignore to next key
						if pubKey != nil {
							// Send prior public key, if any
							keyChan <- pubKey
							pubKey = nil
						}
						log.Println(parseErr)
						pubKey = nil
						currentSignable = nil
						currentUserId = nil
					default:
						log.Println(parseErr)
					}
				}
				//case *packet.UserAttribute:
			}
		}
		if pubKey != nil {
			keyChan <- pubKey
		}
	}()
	return keyChan, errorChan
}

// Read only keys with valid self/cross-signatures from input.
func ReadValidKeys(r io.Reader) (validKeyChan chan *PubKey, validErrorChan chan error) {
	validKeyChan = make(chan *PubKey)
	validErrorChan = make(chan error)
	keyChan, errorChan := ReadKeys(r)
	defer func(){for _ = range keyChan {}}()
	defer func(){for _ = range errorChan {}}()
	go func() {
		defer close(validKeyChan)
		defer close(validErrorChan)
		for {
			select {
			case pubKey, ok := <-keyChan:
				if !ok {
					return
				}
				err := checkValidSignatures(pubKey)
				if err == nil {
					validKeyChan <- pubKey
				} else {
					validErrorChan <- err
				}
			case err, ok := <-errorChan:
				if !ok {
					return
				}
				if err != nil {
					validErrorChan <- err
				}
			}
		}
	}()
	return
}

var MissingSelfSigError error = Errors.New("Missing uid self-signature")
var MissingAttrSelfSigError error = Errors.New("Missing attribute self-signature")
var MissingSubKeySigError error = Errors.New("Missing sub-key signature")

func checkValidSignatures(key *PubKey) (verr error) {
	defer func() {
		if r := recover(); r != nil {
			verr = Errors.New(fmt.Sprintf("%v", r))
		}
	}()
	pkPkt, err := key.Parse()
	pk := pkPkt.(*packet.PublicKey)
	if err != nil {
		return err
	}
	for _, uid := range key.Identities {
		var goodSelfSig *Signature
		for _, sig := range uid.Signatures {
			sigPkt, err := sig.Parse()
			if err != nil {
				return err
			}
			s := sigPkt.(*packet.Signature)
			if (s.SigType == packet.SigTypePositiveCert || s.SigType == packet.SigTypeGenericCert) && s.IssuerKeyId != nil && *s.IssuerKeyId == pk.KeyId {
				if err = pk.VerifyUserIdSignature(uid.Id, s); err == nil {
					goodSelfSig = sig
					break
				}
			}
		}
		if goodSelfSig == nil {
			return MissingSelfSigError
		}
		for _, uat := range uid.Attributes {
			var goodAttrSig *Signature
			for _, sig := range uat.Signatures {
				if err = verifyUserAttributeSignature(uat, key, sig); err == nil {
					goodAttrSig = sig
					break
				}
			}
			if goodAttrSig == nil {
				return MissingAttrSelfSigError
			}
		}
	}
	for _, subKey := range key.SubKeys {
		skPkt, err := subKey.Parse()
		if err != nil {
			return err
		}
		sk := skPkt.(*packet.PublicKey)
		var goodSig *Signature
		for _, sig := range subKey.Signatures {
			sigPkt, err := sig.Parse()
			s := sigPkt.(*packet.Signature)
			if s.SigType != packet.SigTypeSubkeyBinding {
				return errors.StructuralError("subkey signature with wrong type")
			}
			if err = pk.VerifyKeySignature(sk, s); err == nil {
				goodSig = sig
				break
			}
		}
		if goodSig == nil {
			return MissingSubKeySigError
		}
	}
	return nil
}

func verifyUserAttributeSignature(userAttr *UserAttribute, key *PubKey, sig *Signature) error {
	// Get packet signature
	sigPkt, err := sig.Parse()
	if err != nil {
		return err
	}
	s := sigPkt.(*packet.Signature)
	// Get user attribute opaque packet
	opr := packet.NewOpaqueReader(bytes.NewBuffer(userAttr.GetPacket()))
	uatOpaque, err := opr.Next()
	if err != nil {
		return err
	}
	// Get public key opaque packet & typed packet
	opr = packet.NewOpaqueReader(bytes.NewBuffer(key.GetPacket()))
	pkOpaque, err := opr.Next()
	if err != nil {
		return err
	}
	pkPkt, err := key.Parse()
	if err != nil {
		return err
	}
	pk := pkPkt.(*packet.PublicKey)
	// Build up the hash for the signature
	h := s.Hash.New()
	// RFC 4880, section 5.2.4
	// Write the signature prefix and public key contents to hash
	pk.SerializeSignaturePrefix(h)
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
	return pk.VerifySignature(h, s)
}
