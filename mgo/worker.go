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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"launchpad.net/hockeypuck"
	"bitbucket.org/cmars/go.crypto/openpgp"
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
	session.SetMode(mgo.Strong, true)
	c := session.DB("hockeypuck").C("keys")
	index := mgo.Index{
		Key: []string{ "fingerprint" },
		Unique: true,
		DropDups: false,
		Background: false,
		Sparse: false }
	err = c.EnsureIndex(index)
	if err != nil {
		return nil, err
	}
	mw := &MgoWorker{
		session: session,
		c: c,
		hkp:        hkp,
		exitLookup: make(chan bool),
		exitAdd:    make(chan bool)}
	return mw, nil
}

type PacketObject interface {
	GetPacket() []byte
	SetPacket(op *packet.OpaquePacket)
	GetDigest() string
	Traverse(pktObjChan chan PacketObject)
}

type Signable interface {
	AppendSig(sig* Signature)
}

type PubKey struct {
	Fingerprint string
	KeyId uint64
	ShortId uint32
	Algorithm int
	KeyLength uint16
	Signatures []*Signature
	Identities []*UserId
	SubKeys []*SubKey
	Packet []byte
	Digest string
}

func (pubKey *PubKey) AppendSig(sig *Signature) {
	pubKey.Signatures = append(pubKey.Signatures, sig)
}

func (o *PubKey) GetPacket() []byte {
	return o.Packet
}

func (o *PubKey) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (o *PubKey) GetDigest() string {
	return o.Digest
}

func (o *PubKey) Traverse(c chan PacketObject) {
	c <- o
	for _, s := range o.Signatures {
		s.Traverse(c)
	}
	for _, u := range o.Identities {
		u.Traverse(c)
	}
	for _, s := range o.SubKeys {
		s.Traverse(c)
	}
}

type Signature struct {
	SigType int
	IssuerKeyId uint64
	Packet []byte
	Digest string
}

func (o *Signature) GetPacket() []byte {
	return o.Packet
}

func (o *Signature) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (o *Signature) GetDigest() string {
	return o.Digest
}

func (o *Signature) Traverse(c chan PacketObject) {
	c <- o
}

type UserId struct {
	Id string
	Keywords []string
	Signatures []*Signature
	Attributes []*UserAttribute
	Packet []byte
	Digest string
}

func (userId *UserId) AppendSig(sig *Signature) {
	userId.Signatures = append(userId.Signatures, sig)
}

func (o *UserId) GetPacket() []byte {
	return o.Packet
}

func (o *UserId) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (o *UserId) Traverse(c chan PacketObject) {
	c <- o
	for _, s := range o.Signatures {
		s.Traverse(c)
	}
	for _, a := range o.Attributes {
		a.Traverse(c)
	}
}

func (o *UserId) GetDigest() string {
	return o.Digest
}

type UserAttribute struct {
	Signatures []*Signature
	Packet []byte
	Digest string
}

func (o *UserAttribute) GetPacket() []byte {
	return o.Packet
}

func (o *UserAttribute) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (userAttr *UserAttribute) AppendSig(sig *Signature) {
	userAttr.Signatures = append(userAttr.Signatures, sig)
}

func (o *UserAttribute) GetDigest() string {
	return o.Digest
}

func (o *UserAttribute) Traverse(c chan PacketObject) {
	c <- o
	for _, s := range o.Signatures {
		s.Traverse(c)
	}
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

func (o *SubKey) GetPacket() []byte {
	return o.Packet
}

func (o *SubKey) SetPacket(op *packet.OpaquePacket) {
	buf := bytes.NewBuffer([]byte{})
	op.Serialize(buf)
	o.Packet = buf.Bytes()
	o.Digest = hockeypuck.Digest(o.Packet)
}

func (o *SubKey) GetDigest() string {
	return o.Digest
}

func (o *SubKey) Traverse(c chan PacketObject) {
	c <- o
	for _, s := range o.Signatures {
		s.Traverse(c)
	}
}

type keyRingResult struct {
	uuid string
	keyRing []byte
	sha512 string
}

func (mw *MgoWorker) GetKey(keyid string) (string, error) {
	keyid = strings.ToLower(keyid)
	raw, err := hex.DecodeString(keyid)
	if err != nil {
		return "", hockeypuck.InvalidKeyId
	}
	var q *mgo.Query
	switch len(raw) {
	case 4:
		q = mw.c.Find(bson.M{ "shortid": binary.BigEndian.Uint32(raw) })
	case 8:
		q = mw.c.Find(bson.M{ "keyid": binary.BigEndian.Uint64(raw) })
	case 20:
		q = mw.c.Find(bson.M{ "fingerprint": keyid })
	default:
		return "", hockeypuck.InvalidKeyId
	}
	key := new(PubKey)
	err = q.One(key)
	if err == mgo.ErrNotFound {
		return "", hockeypuck.KeyNotFound
	} else if err != nil {
		return "", err
	}
	out := bytes.NewBuffer([]byte{})
	err = writeKey(out, key)
	return string(out.Bytes()), err
}

func writeKey(out io.Writer, key *PubKey) error {
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

func (mw *MgoWorker) FindKeys(search string) (uuids []string, err error) {
	return []string{""}, errors.New("Not Implemented")
}

func (mw *MgoWorker) lookupKey(fp string) (*PubKey, error) {
	pubKey := new(PubKey)
	q := mw.c.Find(bson.M{ "fingerprint": fp })
	err := q.One(pubKey)
	if err == mgo.ErrNotFound {
		return nil, hockeypuck.KeyNotFound
	} else if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (mw *MgoWorker) AddKey(armoredKey string) error {
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(armoredKey))
	if err != nil {
		return err
	}
	keyChan, errChan := readKeys(armorBlock.Body)
	for {
		select {
		case key, moreKeys :=<-keyChan:
			if key != nil {
				lastKey, err := mw.lookupKey(key.Fingerprint)
				if err == nil && lastKey != nil {
					mergeKey(lastKey, key)
					err = mw.c.Update(bson.M{ "fingerprint": key.Fingerprint }, lastKey)
				} else {
					err = mw.c.Insert(key)
				}
			}
			if !moreKeys {
				return err
			}
		case err :=<-errChan:
			return err
		}
	}
	panic("unreachable")
}

func readKeys(r io.Reader) (keyChan chan *PubKey, errorChan chan error) {
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
				fp = hockeypuck.Fingerprint(pk)
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
						KeyId: binary.BigEndian.Uint64(pk.Fingerprint[12:20]),
						ShortId: binary.BigEndian.Uint32(pk.Fingerprint[16:20]),
						Algorithm: int(pk.PubKeyAlgo),
						KeyLength: keyLength }
					pubKey.SetPacket(op)
					currentSignable = pubKey
				} else {
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
				s := p.(*packet.Signature)
				sig := &Signature{
					SigType: int(s.SigType),
					IssuerKeyId: *s.IssuerKeyId }
				sig.SetPacket(op)
				currentSignable.AppendSig(sig)
			case *packet.UserId:
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
				case 17:
					userAttr := &UserAttribute{}
					userAttr.SetPacket(op)
					if currentUserId != nil {
						currentUserId.Attributes = append(currentUserId.Attributes, userAttr)
					}
					currentSignable = userAttr
				case 2:
					// TODO: Check for signature version 3
					;
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

func mergeKey(dstKey *PubKey, srcKey *PubKey) {
	dstObjects := mapKey(dstKey)
	pktObjChan := make(chan PacketObject)
	go func(){
		srcKey.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	// Track src parent object in src traverse
	var srcPubKey *PubKey
	var srcUserId *UserId
	var srcSignable PacketObject
	var srcParent PacketObject
	var hasParent bool
	for srcObj := range pktObjChan {
		switch srcObj.(type) {
		case *PubKey:
			srcPubKey = srcObj.(*PubKey)
			srcSignable = srcObj
			srcParent = nil
			hasParent = false
		case *UserId:
			srcUserId = srcObj.(*UserId)
			srcSignable = srcObj
			srcParent = srcPubKey
			hasParent = true
		case *UserAttribute:
			srcSignable = srcObj
			srcParent = srcUserId
			hasParent = true
		case *SubKey:
			srcSignable = srcObj
			srcParent = srcPubKey
			hasParent = true
		case *Signature:
			srcParent = srcSignable
			hasParent = true
		}
		// match in dst tree
		_, dstHas := dstObjects[srcObj.GetDigest()]
		if dstHas {
			continue  // We already have it
		}
		if hasParent {
			dstParentObj, dstHasParent := dstObjects[srcParent.GetDigest()]
			if dstHasParent {
				appendPacketObject(dstParentObj, srcObj)
			}
		}
	}
}

func mapKey(root PacketObject) (objects map[string]PacketObject) {
	objects = make(map[string]PacketObject)
	pktObjChan := make(chan PacketObject)
	go func() {
		root.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	for pktObj := range pktObjChan {
		objects[pktObj.GetDigest()] = pktObj
	}
	return
}

func appendPacketObject(dstParent PacketObject, srcObj PacketObject) {
	if sig, isa := srcObj.(*Signature); isa {
		if dst, isa := dstParent.(Signable); isa {
			dst.AppendSig(sig)
		}
	} else if uattr, isa := srcObj.(*UserAttribute); isa {
		if uid, isa := dstParent.(*UserId); isa {
			uid.Attributes = append(uid.Attributes, uattr)
		}
	} else if uid, isa := srcObj.(*UserId); isa {
		if pubKey, isa := dstParent.(*PubKey); isa {
			pubKey.Identities = append(pubKey.Identities, uid)
		}
	} else if subKey, isa := srcObj.(*SubKey); isa {
		if pubKey, isa := dstParent.(*PubKey); isa {
			pubKey.SubKeys = append(pubKey.SubKeys, subKey)
		}
	}
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
