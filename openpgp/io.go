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

type OpaquePacketResult struct {
	*packet.OpaquePacket
	Error error
}

type OpaquePacketChan chan *OpaquePacketResult

func IterOpaquePackets(root PacketRecord) OpaquePacketChan {
	c := make(OpaquePacketChan)
	go func() {
		defer close(c)
		root.Visit(func(rec PacketRecord) error {
			op, err := rec.GetOpaquePacket()
			c <- &OpaquePacketResult{op, err}
			if err != nil {
				return err
			}
			return nil
		})
	}()
	return c
}

// SksDigest calculates a cumulative message digest on all
// OpenPGP packets for a given primary public key,
// using the same ordering as SKS, the Synchronizing Key Server.
// Use MD5 for matching digest values with SKS.
func SksDigest(key *Pubkey, h hash.Hash) string {
	var packets packetSlice
	for opkt := range IterOpaquePackets(key) {
		if opkt.Error != nil {
			log.Println("Error parsing packet:", opkt.Error, "public key fingerprint:", key.Fingerprint())
		} else {
			packets = append(packets, opkt.OpaquePacket)
		}
	}
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
		var opkt *packet.OpaquePacket
		var currentPubkey *Pubkey
		var currentSignable Signable
		opktReader := packet.NewOpaqueReader(r)
		for opkt, err = opktReader.Next(); err != io.EOF; opkt, err = opktReader.Next() {
			if err != nil {
				c <- &ReadKeyResult{Error: err}
				return
			}
			pkt, parseErr := opkt.Parse()
			if parseErr == nil {
				switch p := pkt.(type) {
				case *packet.PublicKey:
					if !p.IsSubkey {
						if currentPubkey != nil {
							// New public key found, send prior one
							currentPubkey.updateDigests()
							c <- &ReadKeyResult{Pubkey: currentPubkey}
							currentPubkey = nil
						}
						var pubkey *Pubkey
						if pubkey, err = NewPubkey(p); err != nil {
							currentPubkey = nil
							c <- &ReadKeyResult{Error: err}
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
						var subkey *Subkey
						if subkey, err = NewSubkey(p); err != nil {
							c <- &ReadKeyResult{Error: err}
						}
						currentPubkey.subkeys = append(currentPubkey.subkeys, subkey)
						currentSignable = subkey
					}
				case *packet.Signature:
					if currentSignable == nil {
						c <- ErrReadKeys("Signature outside signable scope in stream")
						continue
					}
					var sig *Signature
					if sig, err = NewSignature(p); err != nil {
						c <- &ReadKeyResult{Error: err}
						continue
					}
					currentSignable.AddSignature(sig)
				case *packet.UserId:
					if currentPubkey == nil {
						c <- ErrReadKeys("User ID outside primary public key scope in stream")
						continue
					}
					var uid *UserId
					if uid, err = NewUserId(p); err != nil {
						c <- &ReadKeyResult{Error: err}
						continue
					}
					currentSignable = uid
					currentPubkey.userIds = append(currentPubkey.userIds, uid)
				case *packet.UserAttribute:
					if currentPubkey == nil {
						c <- ErrReadKeys("User attribute outside primary public key scope in stream")
						continue
					}
					var uat *UserAttribute
					if uat, err = NewUserAttribute(p); err != nil {
						c <- &ReadKeyResult{Error: err}
						continue
					}
					currentSignable = uat
					currentPubkey.userAttributes = append(currentPubkey.userAttributes, uat)
				}
			} else if currentPubkey != nil {
				var unsupp *Unsupported
				if unsupp, err = NewUnsupported(opkt); err != nil {
					c <- &ReadKeyResult{Error: err}
					continue
				}
				currentPubkey.unsupported = append(currentPubkey.unsupported, unsupp)
			} else {
				c <- &ReadKeyResult{Error: parseErr}
			}
		}
		if currentPubkey != nil {
			currentPubkey.updateDigests()
			c <- &ReadKeyResult{Pubkey: currentPubkey}
		}
	}()
	return c
}
