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
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"log"
	"sort"
	"time"
)

// Comparable time flag for "never expires"
var NeverExpires time.Time

var ErrMissingSignature = errors.New("Key material missing an expected signature")

func init() {
	t, err := time.Parse("2006-01-02 15:04:05 -0700", "9999-12-31 23:59:59 +0000")
	if err != nil {
		panic(err)
	}
	NeverExpires = t
}

// Get the public key fingerprint as a hex string.
func Fingerprint(pubkey *packet.PublicKey) string {
	return hex.EncodeToString(pubkey.Fingerprint[:])
}

// Get the public key fingerprint as a hex string.
func FingerprintV3(pubkey *packet.PublicKeyV3) string {
	return hex.EncodeToString(pubkey.Fingerprint[:])
}

func WritePackets(w io.Writer, root PacketRecord) error {
	return root.Visit(func(rec PacketRecord) error {
		op, err := rec.GetOpaquePacket()
		if err != nil {
			return err
		}
		return op.Serialize(w)
	})
}

func WriteArmoredPackets(w io.Writer, root PacketRecord) error {
	armw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	defer armw.Close()
	if err != nil {
		return err
	}
	return WritePackets(armw, root)
}

type OpaqueKeyring struct {
	Packets      []*packet.OpaquePacket
	RFingerprint string
	Md5          string
	Sha256       string
	Error        error
}

type OpaqueKeyringChan chan *OpaqueKeyring

func ReadOpaqueKeyrings(r io.Reader) OpaqueKeyringChan {
	c := make(OpaqueKeyringChan)
	or := packet.NewOpaqueReader(r)
	go func() {
		defer close(c)
		var op *packet.OpaquePacket
		var err error
		var current *OpaqueKeyring
		for op, err = or.Next(); err == nil; op, err = or.Next() {
			switch op.Tag {
			case packet.PacketTypePublicKey:
				if current != nil {
					c <- current
					current = nil
				}
				current = new(OpaqueKeyring)
				fallthrough
			case packet.PacketTypeUserId:
				fallthrough
			case packet.PacketTypeUserAttribute:
				fallthrough
			case packet.PacketTypePublicSubkey:
				fallthrough
			case packet.PacketTypeSignature:
				current.Packets = append(current.Packets, op)
			}
		}
		if err == io.EOF && current != nil {
			c <- current
		} else {
			c <- &OpaqueKeyring{Error: err}
		}
	}()
	return c
}

// SksDigest calculates a cumulative message digest on all
// OpenPGP packets for a given primary public key,
// using the same ordering as SKS, the Synchronizing Key Server.
// Use MD5 for matching digest values with SKS.
func SksDigest(key *Pubkey, h hash.Hash) string {
	var packets packetSlice
	key.Visit(func(rec PacketRecord) error {
		if opkt, err := rec.GetOpaquePacket(); err != nil {
			log.Println("Error parsing packet:", err, "public key fingerprint:", key.Fingerprint())
			return err
		} else {
			packets = append(packets, opkt)
		}
		return nil
	})
	packets = append(packets, key.UnsupportedPackets()...)
	return sksDigestOpaque(packets, h)
}

func sksDigestOpaque(packets []*packet.OpaquePacket, h hash.Hash) string {
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

type ReadKeyResults []*ReadKeyResult

func (r ReadKeyResults) GoodKeys() (result []*Pubkey) {
	for _, rkr := range r {
		if rkr.Error == nil {
			result = append(result, rkr.Pubkey)
		}
	}
	return
}

type PubkeyChan chan *ReadKeyResult

func ErrReadKeys(msg string) *ReadKeyResult {
	return &ReadKeyResult{Error: errors.New(msg)}
}

func (pubkey *Pubkey) updateDigests() {
	pubkey.Md5 = SksDigest(pubkey, md5.New())
	pubkey.Sha256 = SksDigest(pubkey, sha256.New())
}

func ReadKeys(r io.Reader) PubkeyChan {
	c := make(PubkeyChan)
	go func() {
		defer close(c)
		for keyRead := range readKeys(r) {
			if keyRead.Error == nil {
				Resolve(keyRead.Pubkey)
			}
			c <- keyRead
		}
	}()
	return c
}

// Read one or more public keys from input.
func readKeys(r io.Reader) PubkeyChan {
	c := make(PubkeyChan)
	go func() {
		defer close(c)
		var err error
		var pubkey *Pubkey
		var signable Signable
		var pkt packet.Packet
		var parseErr error
		for opkr := range ReadOpaqueKeyrings(r) {
			pubkey = nil
			for _, opkt := range opkr.Packets {
				if pkt, parseErr = opkt.Parse(); parseErr != nil {
					// Deal with opaque package parse errors
					if opkt.Tag == packet.PacketTypePublicKey {
						// If the primary public key cannot be parsed, we'll need to store
						// what we can to sync it.
						if pubkey == nil {
							if pubkey, err = NewInvalidPubkey(opkt); err != nil {
								log.Println("Failed to parse invalid primary pubkey:", opkt)
								panic("Could not create invalid primary pubkey, should not happen!")
							}
						} else {
							// Multiple primary public keys in this keyring? ReadOpaqueKeyings bug.
							log.Println("On pubkey:", pubkey)
							log.Println("Found embedded primary pubkey:", opkt)
							panic("Multiple primary public keys in keyring, should not happen!")
						}
					} else if pubkey == nil {
						// Primary public key not first packet in this keyring? ReadOpaqueKeyings bug.
						panic("Primary public key was not the first packet in OpaqueKeyring, should not happen!")
					} else {
						// Add other packet to primary public key as unsupported keyring trash.
						pubkey.AppendUnsupported(opkt)
					}
					continue
				}
				var badPacket *packet.OpaquePacket
				switch opkt.Tag {
				case packet.PacketTypePublicKey:
					if pubkey != nil {
						log.Println("On pubkey:", pubkey)
						log.Println("Found embedded primary pubkey:", opkt)
						panic("Multiple primary public keys in keyring, should not happen!")
					}
					if pubkey, err = NewPubkey(pkt); err != nil {
						if pubkey, err = NewInvalidPubkey(opkt); err != nil {
							log.Println("Failed to parse invalid primary pubkey:", opkt)
							panic("Could not create invalid primary pubkey, should not happen!")
						}
					} else {
						signable = pubkey
					}
				case packet.PacketTypePublicSubkey:
					if subkey, err := NewSubkey(pkt); err != nil {
						badPacket = opkt
					} else {
						pubkey.subkeys = append(pubkey.subkeys, subkey)
						signable = subkey
					}
				case packet.PacketTypeUserId:
					if userId, err := NewUserId(pkt); err != nil {
						badPacket = opkt
					} else {
						pubkey.userIds = append(pubkey.userIds, userId)
						signable = userId
					}
				case packet.PacketTypeUserAttribute:
					if userAttr, err := NewUserAttribute(pkt); err != nil {
						badPacket = opkt
					} else {
						pubkey.userAttributes = append(pubkey.userAttributes, userAttr)
						signable = userAttr
					}
				case packet.PacketTypeSignature:
					if sig, err := NewSignature(pkt); err != nil {
						badPacket = opkt
					} else if signable == nil {
						badPacket = opkt
					} else {
						signable.AddSignature(sig)
					}
				default:
					badPacket = opkt
				}
				if badPacket != nil {
					pubkey.AppendUnsupported(badPacket)
				}
			}
			if err = pubkey.Validate(); err != nil {
				// Feed back gross syntactical errors, such as packets with no sigs
				c <- &ReadKeyResult{Error: err}
			}
			pubkey.updateDigests()
			// Validate signatures and wire-up relationships.
			// Also flags invalid key material but does not remove it.
			Resolve(pubkey)
			c <- &ReadKeyResult{Pubkey: pubkey}
		}
	}()
	return c
}

func (pubkey *Pubkey) Validate() error {
	for _, uid := range pubkey.userIds {
		if len(uid.signatures) == 0 {
			return ErrMissingSignature
		}
	}
	for _, uat := range pubkey.userAttributes {
		if len(uat.signatures) == 0 {
			return ErrMissingSignature
		}
	}
	for _, subkey := range pubkey.subkeys {
		if len(subkey.signatures) == 0 {
			return ErrMissingSignature
		}
	}
	return nil
}
