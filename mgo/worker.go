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
	"bitbucket.org/cmars/go.crypto/openpgp/armor"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	. "launchpad.net/hockeypuck"
	"strings"
	"time"
)

const UUID_LEN = 43 // log(2**256, 64) = 42.666...

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
	WorkerBase
	PksSender
	Connect string
	session *mgo.Session
	keys    *mgo.Collection
	pksStat *mgo.Collection
}

func (mw *MgoWorker) Init() (err error) {
	mw.WorkerBase.Init()
	mw.PksSender.Init()
	mw.L.Println("Connecting to mongodb:", mw.Connect)
	mw.session, err = mgo.Dial(mw.Connect)
	if err != nil {
		mw.L.Println("Connection failed:", err)
		return
	}
	mw.session.SetMode(mgo.Strong, true)
	// Conservative on writes
	mw.session.EnsureSafe(&mgo.Safe{
		W:     1,
		FSync: true})
	// keys collection stores all the key material
	mw.keys = mw.session.DB("hockeypuck").C("keys")
	// fingerprint index
	fpIndex := mgo.Index{
		Key:        []string{"fingerprint"},
		Unique:     true,
		DropDups:   false,
		Background: false,
		Sparse:     false}
	err = mw.keys.EnsureIndex(fpIndex)
	if err != nil {
		mw.L.Println("Ensure index failed:", err)
		return
	}
	// keyid index
	keyidIndex := mgo.Index{
		Key:        []string{"keyid"},
		Unique:     false,
		DropDups:   false,
		Background: false,
		Sparse:     false}
	err = mw.keys.EnsureIndex(keyidIndex)
	if err != nil {
		mw.L.Println("Ensure index failed:", err)
		return
	}
	// shortid index
	shortidIndex := mgo.Index{
		Key:        []string{"shortid"},
		Unique:     false,
		DropDups:   false,
		Background: false,
		Sparse:     false}
	err = mw.keys.EnsureIndex(shortidIndex)
	if err != nil {
		mw.L.Println("Ensure index failed:", err)
		return
	}
	// uid keyword index
	kwIndex := mgo.Index{
		Key:        []string{"identities.keywords"},
		Unique:     false,
		DropDups:   false,
		Background: true,
		Sparse:     false}
	err = mw.keys.EnsureIndex(kwIndex)
	if err != nil {
		mw.L.Println("Ensure index failed:", err)
		return
	}
	// pks collection stores sync status with downstream servers
	mw.pksStat = mw.session.DB("hockeypuck").C("pksStat")
	// pks addr index
	addrIndex := mgo.Index{
		Key:        []string{"addr"},
		Unique:     true,
		DropDups:   false,
		Background: true,
		Sparse:     false}
	err = mw.pksStat.EnsureIndex(addrIndex)
	if err != nil {
		mw.L.Println("Ensure index failed:", err)
		return
	}
	err = mw.initPksAddrs()
	return
}

func (mw *MgoWorker) LookupKeys(search string, limit int) (keys []*PubKey, err error) {
	q := mw.keys.Find(bson.M{"identities.keywords": search})
	n, err := q.Count()
	if n > limit {
		return keys, TooManyResponses
	}
	pubKey := new(PubKey)
	iter := q.Iter()
	for iter.Next(pubKey) {
		keys = append(keys, pubKey)
		pubKey = new(PubKey)
	}
	err = iter.Err()
	return
}

func (mw *MgoWorker) LookupKey(keyid string) (*PubKey, error) {
	keyid = strings.ToLower(keyid)
	raw, err := hex.DecodeString(keyid)
	if err != nil {
		return nil, InvalidKeyId
	}
	var q *mgo.Query
	switch len(raw) {
	case 4:
		q = mw.keys.Find(bson.M{"shortid": raw})
	case 8:
		q = mw.keys.Find(bson.M{"keyid": raw})
	case 20:
		q = mw.keys.Find(bson.M{"fingerprint": keyid})
	default:
		return nil, InvalidKeyId
	}
	key := new(PubKey)
	err = q.One(key)
	if err == mgo.ErrNotFound {
		return nil, KeyNotFound
	} else if err != nil {
		return nil, err
	}
	return key, nil
}

func (mw *MgoWorker) AddKey(armoredKey string) ([]string, error) {
	mw.L.Print("AddKey(...)")
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(armoredKey))
	if err != nil {
		return []string{}, err
	}
	return mw.LoadKeys(armorBlock.Body)
}

func (mw *MgoWorker) LoadKeys(r io.Reader) (fps []string, err error) {
	keyChan, errChan := ReadKeys(r)
	for {
		select {
		case key, moreKeys := <-keyChan:
			if key != nil {
				var lastKey *PubKey
				lastKey, err = mw.LookupKey(key.Fingerprint)
				if err == nil && lastKey != nil {
					mw.L.Print("Merge/Update:", key.Fingerprint)
					MergeKey(lastKey, key)
					lastKey.Mtime = time.Now().Unix()
					err = mw.keys.Update(bson.M{"fingerprint": key.Fingerprint}, lastKey)
				} else if err == KeyNotFound {
					mw.L.Print("Insert:", key.Fingerprint)
					key.Ctime = time.Now().Unix()
					err = mw.keys.Insert(key)
				}
				if err != nil {
					return
				} else {
					fps = append(fps, key.Fingerprint)
				}
			}
			if !moreKeys {
				return
			}
		case err = <-errChan:
			return
		}
	}
	panic("unreachable")
}
