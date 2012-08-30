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

package mgo

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"launchpad.net/hockeypuck"
	"bitbucket.org/cmars/go.crypto/openpgp/armor"
	"bitbucket.org/cmars/go.crypto/openpgp/packet"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

const UUID_LEN = 43  // log(2**256, 64) = 42.666...

func NewUuid() (string, error) {
	buf := bytes.NewBuffer([]byte{})
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	n, err := io.CopyN(enc, rand.Reader, UUID_LEN)
	if err != nil {
		return "", err
	}
	if n < UUID_LEN {
		return "", errors.New("Failed to generate UUID")
	}
	return string(buf.Bytes()), nil
}

type MgoWorker struct {
	session *mgo.Session
	c *mgo.Collection
	hkp        *hockeypuck.HkpServer
	exitLookup chan bool
	exitAdd    chan bool
}

func NewWorker(hkp *hockeypuck.HkpServer, connect string) (*MgoWorker, error) {
	session, err := mgo.Dial(connect)
	if err != nil {
		return nil, err
	}
	c := session.DB("hockeypuck").C("keys")
	mw := &MgoWorker{
		session: session,
		c: c,
		hkp:        hkp,
		exitLookup: make(chan bool),
		exitAdd:    make(chan bool)}
	return mw, nil
}

type Signable interface {
	AppendSig(sig* Signature)
}

type PubKey struct {
	Fingerprint string
	Algorithm int
	KeyLength uint16
	Signatures []*Signature
	Identities []*UserID
	SubKeys []*SubKey
	Packet []byte
	Digest string
}

func (pubKey *PubKey) AppendSig(sig *Signature) {
	pubKey.Signatures = append(pubKey.Signatures, sig)
}

type Signature struct {
	SigType int
	IssuerKeyId uint64
	Packet []byte
	Digest string
}

type UserID struct {
	Id string
	Signatures []*Signature
	Attributes []*UserAttribute
	Packet []byte
	Digest string
}

func (userId *UserID) AppendSig(sig *Signature) {
	userId.Signatures = append(userId.Signatures, sig)
}

type UserAttribute struct {
	Signatures []*Signature
	Packet []byte
	Digest string
}

type SubKey struct {
	Fingerprint string
	Algorithm int
	KeyLength uint16
	Signatures []*Signature
	Packet []byte
	Digest string
}

func (subKey *SubKey) AppendSig(sig *Signature) {
	subKey.Signatures = append(subKey.Signatures, sig)
}

type keyRingResult struct {
	uuid string
	keyRing []byte
	sha512 string
}

func (mw *MgoWorker) GetKey(keyid string) (string, error) {
	return "", errors.New("Not Implemented")
}

func (mw *MgoWorker) FindKeys(search string) (uuids []string, err error) {
	return []string{""}, errors.New("Not Implemented")
}

func (mw *MgoWorker) lookupKey(fp string) (*PubKey, error) {
	return nil, errors.New("Not Implemented")
}

func (mw *MgoWorker) AddKey(armoredKey string) (err error) {
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(armoredKey))
	if err != nil {
		return
	}
	var last Signable
	or := packet.NewOpaqueReader(armorBlock.Body)
	var p packet.Packet
	var op *packet.OpaquePacket
	var pubKey *PubKey
	var lastKey *PubKey
	var fp string
	for op, err = or.Next(); err != io.EOF; op, err = or.Next() {
		if err != nil {
			return
		}
		p, err = op.Parse()
		switch p.(type) {
		case *packet.PublicKey:
			pk := p.(*packet.PublicKey)
			fp = hockeypuck.Fingerprint(pk)
			//lastKey, err = mw.lookupKey(fp)
			lastKey, err = nil, nil
			if err != nil {
				return
			}
			keyLength, err := pk.BitLength()
			if err != nil {
				return err
			}
			if !pk.IsSubkey {
				if pubKey != nil {
					// Only read the first public key
					return err
				}
				// This is the primary public key
				pubKey = &PubKey{
					Fingerprint: fp,
					Algorithm: int(pk.PubKeyAlgo),
					KeyLength: keyLength,
					Packet: op.Contents,
					Digest: hockeypuck.Sha512(op.Contents) }
				last = pubKey
			} else {
				// This is a sub key
				subKey := &SubKey{
					Fingerprint: fp,
					Algorithm: int(pk.PubKeyAlgo),
					KeyLength: keyLength,
					Packet: op.Contents,
					Digest: hockeypuck.Sha512(op.Contents) }
				pubKey.SubKeys = append(pubKey.SubKeys, subKey)
				last = subKey
			}
		case *packet.Signature:
			s := p.(*packet.Signature)
			sig := &Signature{
				SigType: int(s.SigType),
				IssuerKeyId: *s.IssuerKeyId,
				Packet: op.Contents,
				Digest: hockeypuck.Sha512(op.Contents) }
			last.AppendSig(sig)
		case *packet.UserId:
			uid := p.(*packet.UserId)
			userId := &UserID{
				Id: uid.Id,
				Packet: op.Contents,
				Digest: hockeypuck.Sha512(op.Contents) }
			last = userId
			pubKey.Identities = append(pubKey.Identities, userId)
		//case *packet.UserAttribute:
		}
	}
	if lastKey != nil {
		err = mw.mergeKey(pubKey, lastKey)
		if err == nil {
			err = mw.c.Update(bson.M{ "fingerprint": fp }, pubKey)
		}
	} else {
		err = mw.c.Insert(pubKey)
	}
	return
}


func (mw *MgoWorker) mergeKey(pubKey *PubKey, mergeKey *PubKey) (err error) {
	return errors.New("Not implemented")
}

func (mw *MgoWorker) Start() {
	go func() {
		for shouldRun := true; shouldRun; {
			select {
			case lookup := <-mw.hkp.LookupRequests:
				switch lookup.Op {
				case hockeypuck.Get:
					if lookup.Exact || strings.HasPrefix(lookup.Search, "0x") {
						armor, err := mw.GetKey(lookup.Search[2:])
						lookup.Response() <- &response{ content: armor, err: err }
					} else {
						lookup.Response() <- &notImplementedError{}
					}
				default:
					lookup.Response() <- &notImplementedError{}
				}
			case _ = <-mw.exitLookup:
				shouldRun = false
			}
		}
	}()
	go func() {
		for shouldRun := true; shouldRun; {
			select {
			case add := <-mw.hkp.AddRequests:
				err := mw.AddKey(add.Keytext)
				add.Response() <- &response{ err: err }
			case _ = <-mw.exitAdd:
				shouldRun = false
			}
		}
	}()
}

func (mw *MgoWorker) Stop() {
	mw.exitLookup <- true
	mw.exitAdd <- true
	// TODO: close session after both exit
}

type response struct {
	content string
	err error
}

func (r *response) Error() error {
	return r.err
}

func (r *response) WriteTo(w http.ResponseWriter) error {
	w.Write([]byte(r.content))
	return r.err
}

type notImplementedError struct {
}

func (e *notImplementedError) Error() error {
	return errors.New("Not implemented")
}

func (e *notImplementedError) WriteTo(_ http.ResponseWriter) error {
	return e.Error()
}
