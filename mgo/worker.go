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
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"launchpad.net/hockeypuck"
	"bitbucket.org/cmars/go.crypto/openpgp/armor"
	"bitbucket.org/cmars/go.crypto/openpgp/packet"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

const UUID_LEN = 43  // log(2**256, 64) = 42.666...

const FIND_KEYS_LIMIT = 10
const INDEX_LIMIT = 50

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
	l *log.Logger
	hkp        *hockeypuck.HkpServer
	exitLookup chan bool
	exitAdd    chan bool
}

func NewWorker(hkp *hockeypuck.HkpServer, connect string, l *log.Logger) (*MgoWorker, error) {
	if l == nil {
		l = log.New(os.Stderr, "[hockeypuck]", log.LstdFlags | log.Lshortfile)
	}
	l.Println("Connecting to mongodb:", connect)
	session, err := mgo.Dial(connect)
	if err != nil {
		l.Println("Connection failed:", err)
		return nil, err
	}
	session.SetMode(mgo.Strong, true)
	c := session.DB("hockeypuck").C("keys")
	fpIndex := mgo.Index{
		Key: []string{ "fingerprint" },
		Unique: true,
		DropDups: false,
		Background: false,
		Sparse: false }
	err = c.EnsureIndex(fpIndex)
	if err != nil {
		l.Println("Ensure index failed:", err)
		return nil, err
	}
	kwIndex := mgo.Index{
		Key: []string{ "identities.keywords" },
		Unique: false,
		DropDups: false,
		Background: true,
		Sparse: false }
	err = c.EnsureIndex(kwIndex)
	if err != nil {
		l.Println("Ensure index failed:", err)
		return nil, err
	}
	mw := &MgoWorker{
		session: session,
		c: c,
		hkp:        hkp,
		l: l,
		exitLookup: make(chan bool),
		exitAdd:    make(chan bool)}
	return mw, nil
}

func (mw *MgoWorker) GetKey(keyid string) (string, error) {
	mw.l.Print("GetKey(", keyid, ")")
	key, err := mw.lookupKey(keyid)
	if err != nil {
		return "", hockeypuck.InvalidKeyId
	}
	out := bytes.NewBuffer([]byte{})
	err = writeKey(out, key)
	mw.l.Println(err)
	return string(out.Bytes()), err
}

func (mw *MgoWorker) FindKeys(search string) (string, error) {
	mw.l.Print("FindKeys(", search, ")")
	keys, err := mw.lookupKeys(search, FIND_KEYS_LIMIT)
	if err != nil {
		return "", err
	}
	if len(keys) == 0 {
		return "", hockeypuck.KeyNotFound
	}
	mw.l.Print(len(keys), "matches")
	buf := bytes.NewBuffer([]byte{})
	for _, key := range keys {
		err = writeKey(buf, key)
		if err != nil {
			return "", err
		}
	}
	return string(buf.Bytes()), err
}

func (mw *MgoWorker) lookupKeys(search string, limit int) (keys []*PubKey, err error) {
	q := mw.c.Find(bson.M{ "identities.keywords": search })
	n, err := q.Count()
	if n > limit {
		return keys, hockeypuck.TooManyResponses
	}
	pubKey := new(PubKey)
	iter := q.Iter()
	for iter.Next(pubKey) {
		keys = append(keys, pubKey)
	}
	err = iter.Err()
	return
}

func (mw *MgoWorker) lookupKey(keyid string) (*PubKey, error) {
	keyid = strings.ToLower(keyid)
	raw, err := hex.DecodeString(keyid)
	if err != nil {
		return nil, hockeypuck.InvalidKeyId
	}
	var q *mgo.Query
	switch len(raw) {
	case 4:
		q = mw.c.Find(bson.M{ "shortid": raw })
	case 8:
		q = mw.c.Find(bson.M{ "keyid": raw })
	case 20:
		q = mw.c.Find(bson.M{ "fingerprint": keyid })
	default:
		return nil, hockeypuck.InvalidKeyId
	}
	key := new(PubKey)
	err = q.One(key)
	if err == mgo.ErrNotFound {
		return nil, hockeypuck.KeyNotFound
	} else if err != nil {
		return nil, err
	}
	return key, nil
}

func (mw *MgoWorker) AddKey(armoredKey string) error {
	mw.l.Print("AddKey(...)")
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(armoredKey))
	if err != nil {
		return err
	}
	return mw.LoadKeys(armorBlock.Body)
}

func (mw *MgoWorker) LoadKeys(r io.Reader) (err error) {
	keyChan, errChan := readKeys(r)
	for {
		select {
		case key, moreKeys :=<-keyChan:
			if key != nil {
				lastKey, err := mw.lookupKey(key.Fingerprint)
				if err == nil && lastKey != nil {
					mw.l.Print("Merge/Update:", key.Fingerprint)
					mergeKey(lastKey, key)
					err = mw.c.Update(bson.M{ "fingerprint": key.Fingerprint }, lastKey)
				} else if err == hockeypuck.KeyNotFound {
					mw.l.Print("Insert:", key.Fingerprint)
					err = mw.c.Insert(key)
				}
				if err != nil {
					return err
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

func (mw *MgoWorker) Start() {
	go func() {
		for shouldRun := true; shouldRun; {
			select {
			case lookup := <-mw.hkp.LookupRequests:
				switch lookup.Op {
				case hockeypuck.Get:
					if lookup.Exact || strings.HasPrefix(lookup.Search, "0x") {
						armor, err := mw.GetKey(lookup.Search[2:])
						mw.l.Println("errors:", err)
						lookup.Response() <- &response{ content: armor, err: err }
					} else {
						armor, err := mw.FindKeys(lookup.Search)
						mw.l.Println("errors:", err)
						lookup.Response() <- &response{ content: armor, err: err }
					}
				case hockeypuck.Index, hockeypuck.Vindex:
					var key *PubKey
					var err error
					keys := []*PubKey{}
					if lookup.Exact || strings.HasPrefix(lookup.Search, "0x") {
						key, err = mw.lookupKey(lookup.Search[2:])
						keys = append(keys, key)
					} else {
						keys, err = mw.lookupKeys(lookup.Search, INDEX_LIMIT)
					}
					lookup.Response() <- &indexResponse{ keys: keys, err: err, lookup: lookup }
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
				mw.l.Println("errors:", err)
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

type indexResponse struct {
	lookup *hockeypuck.Lookup
	keys []*PubKey
	err error
}

func (r *indexResponse) Error() error {
	return r.err
}

func (r *indexResponse) WriteTo(w http.ResponseWriter) error {
	err := r.err
	var writeFn func(io.Writer, *PubKey) error = nil
	switch {
	case r.lookup.Option & hockeypuck.MachineReadable != 0:
		writeFn = writeMachineReadable
	case r.lookup.Op == hockeypuck.Vindex:
		writeFn = writeVindex
	case r.lookup.Op == hockeypuck.Index:
		writeFn = writeIndex
	}
	if r.lookup.Option & hockeypuck.MachineReadable != 0 {
		writeFn = writeMachineReadable
		w.Header().Add("Content-Type", "text/plain")
	} else {
		w.Header().Add("Content-Type", "text/html")
		w.Write([]byte(`<html><body><pre>`))
		w.Write([]byte(`<table>
<tr><th>Type</th><th>bits/keyID</th><th>Created</th><th></th></tr>`))
	}
	if writeFn == nil {
		err = hockeypuck.UnsupportedOperation
	}
	if len(r.keys) == 0 {
		err = hockeypuck.KeyNotFound
	}
	if err == nil {
		for _, key := range r.keys {
			err = writeFn(w, key)
		}
	} else {
		w.Write([]byte(err.Error()))
	}
	if r.lookup.Option & hockeypuck.MachineReadable == 0 {
		if r.lookup.Op == hockeypuck.Index {
			w.Write([]byte(`</table>`))
		}
		w.Write([]byte(`</pre></body></html>`))
	}
	return err
}

func AlgorithmCode(algorithm int) string {
	switch packet.PublicKeyAlgorithm(algorithm) {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		return "R"
	case packet.PubKeyAlgoElGamal:
		return "g"
	case packet.PubKeyAlgoDSA:
		return "D"
	}
	return fmt.Sprintf("[%d]", algorithm)
}

func writeIndex(w io.Writer, key *PubKey) error {
	pktObjChan := make(chan PacketObject)
	go func() {
		key.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	for pktObj := range pktObjChan {
		switch pktObj.(type) {
		case *PubKey:
			pubKey := pktObj.(*PubKey)
			pkt, err := pubKey.Parse()
			if err != nil {
				return err
			}
			pk := pkt.(*packet.PublicKey)
			fmt.Fprintf(w, `<tr>
<td>pub</td>
<td>%d%s/<a href="/pks/lookup?op=get&search=0x%s">%s</a></td>
<td>%v</td>
<td></td></tr>`,
				key.KeyLength, AlgorithmCode(key.Algorithm), key.Fingerprint,
				strings.ToUpper(key.Fingerprint[32:40]),
				pk.CreationTime.Format("2006-01-02"))
		case *UserId:
			uid := pktObj.(*UserId)
			fmt.Fprintf(w, `<tr><td>uid</td><td colspan='2'></td>
<td><a href="/pks/lookup?op=vindex&search=0x%s">%s</a></td></tr>`,
				key.Fingerprint, html.EscapeString(uid.Id))
		}
	}
	return nil
}

func writeVindex(w io.Writer, key *PubKey) error {
	pktObjChan := make(chan PacketObject)
	go func() {
		key.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	for pktObj := range pktObjChan {
		switch pktObj.(type) {
		case *PubKey:
			pubKey := pktObj.(*PubKey)
			pkt, err := pubKey.Parse()
			if err != nil {
				return err
			}
			pk := pkt.(*packet.PublicKey)
			fmt.Fprintf(w, `<tr>
<td>pub</td>
<td>%d%s/<a href="/pks/lookup?op=get&search=0x%s">%s</a></td>
<td>%v</td>
<td></td></tr>`,
				key.KeyLength, AlgorithmCode(key.Algorithm), key.Fingerprint,
				strings.ToUpper(key.Fingerprint[32:40]),
				pk.CreationTime.Format("2006-01-02"))
		case *UserId:
			uid := pktObj.(*UserId)
			fmt.Fprintf(w, `<tr><td>uid</td><td colspan='2'></td>
<td><a href="/pks/lookup?op=vindex&search=0x%s">%s</a></td></tr>`,
				key.Fingerprint, html.EscapeString(uid.Id))
		case *Signature:
			sig := pktObj.(*Signature)
			longId := strings.ToUpper(hex.EncodeToString(sig.IssuerKeyId))
			pkt, err := sig.Parse()
			if err != nil {
				return err
			}
			sigv4, isa := pkt.(*packet.Signature)
			var sigTime string
			if isa {
				sigTime = sigv4.CreationTime.Format("2006-01-02")
			}
			fmt.Fprintf(w, `<tr><td>sig</td><td>%s</td><td>%s</td>
<td><a href="/pks/lookup?op=vindex&search=0x%s">%s</a></td></tr>`,
				longId[8:16], sigTime, longId, longId)
/*
		case *UserAttribute:
			uattr := pktObj.(*UserAttribute)
			pkt, err := uattr.Parse()
			if err != nil {
				continue
			}
			if opkt, isa := pkt.(*packet.OpaquePacket); isa {
				fmt.Fprintf(w, `<tr><td>uattr</td><td colspan=2></td>
<td><img src="data:image/jpeg;base64,%s"></img></td></tr>`,
					base64.URLEncoding.EncodeToString(opkt.Contents[22:]))
			}
*/
		}
	}
	return nil
}

func writeMachineReadable(w io.Writer, key *PubKey) error {
	return hockeypuck.UnsupportedOperation
}

type notImplementedError struct {
}

func (e *notImplementedError) Error() error {
	return errors.New("Not implemented")
}

func (e *notImplementedError) WriteTo(_ http.ResponseWriter) error {
	return e.Error()
}
