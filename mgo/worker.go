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
	"code.google.com/p/go.crypto/openpgp/armor"
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
	*MgoClient
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
					lastCuml := lastKey.CumlDigest
					MergeKey(lastKey, key)
					lastKey.CumlDigest = CumlDigest(lastKey)
					if lastKey.CumlDigest != lastCuml {
						mw.l.Print("Updated:", key.Fingerprint)
						lastKey.Mtime = time.Now().UnixNano()
						err = mw.keys.Update(bson.M{"fingerprint": key.Fingerprint}, lastKey)
					} else {
						mw.l.Print("Update: skipped, no change in cumulative digest")
					}
				} else if err == KeyNotFound {
					mw.l.Print("Insert:", key.Fingerprint)
					key.Ctime = time.Now().UnixNano()
					key.Mtime = key.Ctime
					key.CumlDigest = CumlDigest(key)
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

func (mw *MgoWorker) Status() (status *ServerStatus, err error) {
	status = &ServerStatus{PksPeers: lastPksStatus, Version: Version}
	for keyStat := range mw.KeyStatsHourly() {
		status.KeyStatsHourly = append(status.KeyStatsHourly, keyStat)
	}
	for keyStat := range mw.KeyStatsDaily() {
		status.KeyStatsDaily = append(status.KeyStatsDaily, keyStat)
	}
	status.TotalKeys, err = mw.keys.Count()
	if err != nil {
		return
	}
	return
}
