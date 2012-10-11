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
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"regexp"
	"strings"
	"time"
	"bitbucket.org/cmars/go.crypto/openpgp"
	"bitbucket.org/cmars/go.crypto/openpgp/armor"
	"bitbucket.org/cmars/go.crypto/openpgp/packet"
)

const NeverExpires = int64((1<<63)-1)

func Fingerprint(pubkey *packet.PublicKey) string {
	return hex.EncodeToString(pubkey.Fingerprint[:])
}

func Digest(data []byte) string {
	h := sha512.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func WriteKey(out io.Writer, key *PubKey) error {
	w, err := armor.Encode(out, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	defer w.Close()
	pktObjChan := make(chan PacketObject)
	go func(){
		key.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	for pktObj := range pktObjChan {
		_, err = w.Write(pktObj.GetPacket())
		if err != nil {
			close(pktObjChan)
			return err
		}
	}
	return nil
}

func ReadKeys(r io.Reader) (keyChan chan *PubKey, errorChan chan error) {
	keyChan = make(chan *PubKey)
	errorChan = make(chan error)
	go func(){
		defer close(keyChan)
		defer close(errorChan)
		var err error
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
			p, err = op.Parse()
			if err != nil {
				errorChan <- err
				return
			}
			switch p.(type) {
			case *packet.PublicKey:
				pk := p.(*packet.PublicKey)
				fp = Fingerprint(pk)
				keyLength, err := pk.BitLength()
				if err != nil {
					errorChan <- err
					return
				}
				if !pk.IsSubkey {
					if pubKey != nil {
						keyChan <- pubKey
					}
					// This is the primary public key
					pubKey = &PubKey{
						Fingerprint: fp,
						KeyId: pk.Fingerprint[12:20],
						ShortId: pk.Fingerprint[16:20],
						Algorithm: int(pk.PubKeyAlgo),
						KeyLength: keyLength }
					pubKey.SetPacket(op)
					currentSignable = pubKey
				} else {
					if pubKey == nil {
						continue
					}
					// This is a sub key
					subKey := &SubKey{
						Fingerprint: fp,
						Algorithm: int(pk.PubKeyAlgo),
						KeyLength: keyLength }
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
							pubKey.Fingerprint)
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
				sig := &Signature{
					SigType: int(s.SigType),
					IssuerKeyId: issuerKeyId[:],
					CreationTime: s.CreationTime.Unix(),
					SigExpirationTime: sigExpirationTime,
					KeyExpirationTime: keyExpirationTime }
				sig.SetPacket(op)
				currentSignable.AppendSig(sig)
			case *packet.UserId:
				if pubKey == nil {
					continue
				}
				uid := p.(*packet.UserId)
				userId := &UserId{
					Id: uid.Id,
					Keywords: splitUserId(uid.Id) }
				userId.SetPacket(op)
				currentSignable = userId
				currentUserId = userId
				pubKey.Identities = append(pubKey.Identities, userId)
			case *packet.OpaquePacket:
				// Packets not yet supported by go.crypto/openpgp
				switch op.Tag {
				case 17:  // Process user attribute packet
					userAttr := &UserAttribute{}
					userAttr.SetPacket(op)
					if currentUserId != nil {
						currentUserId.Attributes = append(currentUserId.Attributes, userAttr)
					}
					currentSignable = userAttr
				case 2:  // Bad signature packet
					// TODO: Check for signature version 3
					log.Println("Unsupported signature packet, skipping...")
					;
				case 6:  // Bad public key packet
					// TODO: Check for unsupported PGP public key packet version
					// For now, clear state, ignore to next key
					log.Println("Unsupported public key packet, skipping...")
					pubKey = nil
					currentSignable = nil
					currentUserId = nil
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

func splitUserId(id string) []string {
	splitUidRegex, _ := regexp.Compile("\\S+")
	result := splitUidRegex.FindAllString(id, -1)
	for i, s := range result {
		result[i] = strings.Trim(s, "<>")
	}
	return result
}
