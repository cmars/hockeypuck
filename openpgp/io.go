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

func WriteTo(w io.Writer, root PacketRecord) error {
	return root.Visit(func(rec PacketRecord) error {
		op, err := rec.GetPacket()
		if err != nil {
			return err
		}
		return op.Serialize(w)
	})
}

type OpaquePacketChan chan struct {
	*packet.OpaquePacket
	err error
}

func IterOpaquePackets(root PacketRecord) OpaquePacketChan {
	c := make(OpaquePacketChan)
	go func(){
		defer close(c)
		root.Visit(func(rec PacketRecord) error {
			op, err := rec.GetPacket()
			c <- make(struct{op, err})
			if err != nil {
				return err
			}
		})
	}()
	return c
}

// SksDigest calculates a cumulative message digest on all
// OpenPGP packets for a given primary public key,
// using the same ordering as SKS, the Synchronizing Key Server.
// Use MD5 for matching digest values with SKS.
func SksDigest(key *Pubkey, h crypto.Hash) string {
	var packets packetSlice
	for opkt := IterPackets(key) {
		packets = append(packets, opkt.OpaquePacket)
	}
	sort.Sort(sksPacketSorter{packets})
	for _, opkt := range packets {
		binary.Write(h, binary.BigEndian, int32(opkt.Tag))
		binary.Write(h, binary.BigEndian, int32(len(opkt.Contents)))
		h.Write(opkt.Contents)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type ReadKeyResult struct {
	*Pubkey
	Error error
}

type PubkeyChan chan *ReadKeyResult

func ErrReadKeys(msg string) *ReadKeyResult {
	return &ReadKeyResult{Error:errors.New(msg)}
}

// Read one or more public keys from input.
func ReadKeys(r io.Reader) PubkeyChan {
	c := make(PubkeyChan)
	go func() {
		defer close(c)
		var err error
		var parseErr error
		var opkt *packet.OpaquePacket
		var currentPubkey *Pubkey
		var currentSignable Signable
		var fingerprint string
		opktReader := packet.NewOpaqueReader(r)
		for opkt, err = opktReader.Next(); err != io.EOF; opkt, err = opktReader.Next() {
			if err != nil {
				c <- &ReadKeyResult{Error:err}
				return
			}
			pkt, parseErr = op.Parse()
			if parseErr == nil {
				switch p := pkt.(type) {
				case *packet.PublicKey:
					if !p.IsSubkey {
						if currentPubkey != nil {
							// New public key found, send prior one
							c <- currentPubkey
							currentPubkey = nil
						}
						pubkey := new(Pubkey)
						if err = pubkey.SetPublicKey(p); err != nil {
							currentPubkey = nil
							c <- &ReadKeyResult{Error:err}
							continue
						}
						currentPubkey = pubkey
						currentSignable = currentPubkey
					} else {
						if currentPubkey == nil {
							c <- ErrReadKeys(
								"Subkey outside of primary public key scope in stream")
							continue
						}
						// This is a sub key
						subkey := new(Subkey)
						if err = subkey.SetPublicKey(p); err != nil {
							c <- &ReadKeyResult{Error:err}
						}
						currentPubkey.Subkeys = append(currentPubkey.Subkeys, subkey)
						currentSignable = subkey
					}
				case *packet.Signature:
					if currentSignable == nil {
						c <- ErrReadKeys("Signature outside signable scope in stream")
						continue
					}
					sig := new(Signature)
					if err = sig.SetSignature(p); err != nil {
						c <- &ReadKeyResult{Error:err}
						continue
					}
					currentSignable.AddSignature(sig)
				case *packet.UserId:
					if currentPubkey == nil {
						c <- ErrReadKeys("User ID outside primary public key scope in stream")
						continue
					}
					uid := new(UserId)
					if err = uid.SetUserId(p); err != nil {
						c <- &ReadKeyResult{Error:err}
						continue
					}
					currentSignable = uid
					currentPubkey.UserIds = append(currentPubkey.UserIds, uid)
				}
			}
			if _, isUnknown := parseErr.(errors.UnknownPacketTypeError); isUnknown {
				// Packets not yet supported by go.crypto/openpgp
				switch opkt.Tag {
				case 17: // Process user attribute packet
					if currentPubkey == nil {
						c <- ErrReadKeys(
							"User attribute outside primary public key scope in stream")
						continue
					}
					uat := new(UserAttribute)
					if err = uat.SetPacket(op); err != nil {
						c <- &ReadKeyResult{Error:err}
						continue
					}
					currentSignable = uat
					currentPubkey.UserAttributes = append(currentPubkey.UserAttributes, uat)
				case 2: // Bad signature packet
					// TODO: Check for signature version 3
					c <- &ReadKeyResult{Error:parseErr}
				case 6: // Bad public key packet
					// TODO: Check for unsupported PGP public key packet version
					// For now, clear state, ignore to next key
					if currentPubkey != nil {
						// Send prior public key, if any
						c <- &ReadKeyResult{currentPubkey}
						currentPubkey = nil
					}
					c <- &ReadKeyResult{Error:parseErr}
					currentPubkey = nil
					currentSignable = nil
				default:
					c <- &ReadKeyResult{Error:parseErr}
				}
			}
		}
		if currentPubkey != nil {
			c <- &ReadKeyResult(currentPubkey)
		}
	}()
	return c
}

// Read only keys with valid self/cross-signatures from input.
func ReadValidKeys(r io.Reader) (validKeyChan chan *PubKey, validErrorChan chan error) {
	validKeyChan = make(chan *PubKey)
	validErrorChan = make(chan error)
	keyChan, errorChan := ReadKeys(r)
	go func() {
		defer func() {
			for _ = range keyChan {
			}
		}()
		defer func() {
			for _ = range errorChan {
			}
		}()
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
