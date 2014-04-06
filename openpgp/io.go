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
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"time"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
)

// Comparable time flag for "never expires"
var NeverExpires time.Time

var ErrMissingSignature = fmt.Errorf("Key material missing an expected signature")

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
	err := root.Visit(func(rec PacketRecord) error {
		op, err := rec.GetOpaquePacket()
		if err != nil {
			return err
		}
		return op.Serialize(w)
	})
	if err != nil {
		return err
	}
	// Dump unsupported packets at the end.
	pubkey := root.(*Pubkey)
	for _, op := range pubkey.UnsupportedPackets() {
		err = op.Serialize(w)
		if err != nil {
			return err
		}
	}
	return nil
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
	Position     int64
}

func (ok *OpaqueKeyring) setPosition(r io.Reader) {
	if f, is := r.(*os.File); is {
		var err error
		ok.Position, err = f.Seek(0, 1)
		if err != nil {
			ok.Position = -1
		}
	} else {
		ok.Position = -1
	}
}

func (ok *OpaqueKeyring) Parse() (*Pubkey, error) {
	var err error
	var pubkey *Pubkey
	var signable Signable
	pubkey = nil
	for _, opkt := range ok.Packets {
		var badPacket *packet.OpaquePacket
		if opkt.Tag == 6 { //packet.PacketTypePublicKey:
			if pubkey != nil {
				return nil, fmt.Errorf("Multiple public keys in keyring")
			}
			if pubkey, err = NewPubkey(opkt); err != nil {
				return nil, fmt.Errorf("Failed to parse primary public key")
			}
			signable = pubkey
		} else if pubkey != nil {
			switch opkt.Tag {
			case 14: //packet.PacketTypePublicSubkey:
				var subkey *Subkey
				if subkey, err = NewSubkey(opkt); err != nil {
					badPacket = opkt
					signable = nil
				} else {
					pubkey.subkeys = append(pubkey.subkeys, subkey)
					signable = subkey
				}
			case 13: //packet.PacketTypeUserId:
				var userId *UserId
				if userId, err = NewUserId(opkt); err != nil {
					badPacket = opkt
					signable = nil
				} else {
					pubkey.userIds = append(pubkey.userIds, userId)
					signable = userId
				}
			case 17: //packet.PacketTypeUserAttribute:
				var userAttr *UserAttribute
				if userAttr, err = NewUserAttribute(opkt); err != nil {
					badPacket = opkt
					signable = nil
				} else {
					pubkey.userAttributes = append(pubkey.userAttributes, userAttr)
					signable = userAttr
				}
			case 2: //packet.PacketTypeSignature:
				var sig *Signature
				if sig, err = NewSignature(opkt); err != nil {
					badPacket = opkt
					signable = nil
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
	}
	if pubkey == nil {
		return nil, fmt.Errorf("No primary public key found")
	}
	// Update the overall public key material digest.
	pubkey.updateDigests()
	// Validate signatures and wire-up relationships.
	// Also flags invalid key material but does not remove it.
	Resolve(pubkey)
	return pubkey, nil
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
			case 6: //packet.PacketTypePublicKey:
				if current != nil {
					c <- current
					current = nil
				}
				current = new(OpaqueKeyring)
				current.setPosition(r)
				fallthrough
			case 13: //packet.PacketTypeUserId:
				fallthrough
			case 17: //packet.PacketTypeUserAttribute:
				fallthrough
			case 14: //packet.PacketTypePublicSubkey:
				fallthrough
			case 2: //packet.PacketTypeSignature:
				current.Packets = append(current.Packets, op)
			}
		}
		if err == io.EOF && current != nil {
			c <- current
		} else if err != nil {
			if current == nil {
				current = &OpaqueKeyring{}
			}
			current.Error = err
			c <- current
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
			panic(fmt.Sprintf(
				"Error parsing packet: %v public key fingerprint: %v", err, key.Fingerprint()))
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
	return &ReadKeyResult{Error: fmt.Errorf(msg)}
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
		for opkr := range ReadOpaqueKeyrings(r) {
			pubkey, err := opkr.Parse()
			if err != nil {
				c <- &ReadKeyResult{Error: err}
			} else {
				c <- &ReadKeyResult{Pubkey: pubkey}
			}
		}
	}()
	return c
}
