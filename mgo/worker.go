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
	"encoding/hex"
	"fmt"
	"io"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	. "launchpad.net/hockeypuck"
	"strings"
	"time"
)

type StatKeyChan chan *PubKey

type MgoWorker struct {
	*MgoClient
	createdKeys  StatKeyChan
	modifiedKeys StatKeyChan
}

func NewMgoWorker(client *MgoClient) *MgoWorker {
	worker := &MgoWorker{MgoClient: client,
		createdKeys:  make(StatKeyChan, 10),
		modifiedKeys: make(StatKeyChan, 10)}
	go worker.updateStats()
	return worker
}

func (mw *MgoWorker) LookupKeys(search string, limit int) (keys []*PubKey, err error) {
	q := mw.keys.Find(bson.M{"identities.keywords": bson.M{"$all": SplitUserId(search)}})
	n, err := q.Count()
	if n > limit {
		return keys, TooManyResponses
	}
	pubKey := new(PubKey)
	iter := q.Iter()
	for iter.Next(pubKey) {
		mw.addSignatureUids(pubKey)
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
	rkeyid := Reverse(keyid)
	switch len(raw) {
	case 4:
		fallthrough
	case 8:
		q = mw.keys.Find(bson.M{"rfingerprint": bson.RegEx{
			Pattern: fmt.Sprintf("^%s", rkeyid)}})
	case 20:
		q = mw.keys.Find(bson.M{"rfingerprint": rkeyid})
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
	mw.addSignatureUids(key)
	return key, nil
}

func (mw *MgoWorker) addSignatureUids(key *PubKey) (err error) {
	pktChan := make(chan PacketObject)
	go func() {
		key.Traverse(pktChan)
		close(pktChan)
	}()
	for pktObj := range pktChan {
		if sig, is := pktObj.(*Signature); is {
			if sig.IssuerUid == "" {
				result := &struct{ Identities []*struct{ Id string } }{}
				//Id string }}//make(map[string]interface{})
				q := mw.keys.Find(bson.M{"rfingerprint": bson.RegEx{Pattern: fmt.Sprintf("^%s", sig.RIssuerKeyId)}})
				q.Select(bson.M{"identities.id": 1})
				err = q.One(result)
				if err != nil {
					return
				}
				if len(result.Identities) > 0 {
					sig.IssuerUid = result.Identities[0].Id
				}
			}
		}
	}
	return
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
	keyChan, errChan := ReadValidKeys(r)
	for {
		select {
		case key, moreKeys := <-keyChan:
			if key != nil {
				var lastKey *PubKey
				lastKey, err = mw.LookupKey(key.Fingerprint())
				if err == nil && lastKey != nil {
					lastCuml := lastKey.CumlDigest
					MergeKey(lastKey, key)
					lastKey.CumlDigest = CumlDigest(lastKey)
					if lastKey.CumlDigest != lastCuml {
						mw.l.Print("Updated:", key.Fingerprint())
						lastKey.Mtime = time.Now().UnixNano()
						err = mw.keys.Update(bson.M{"fingerprint": key.Fingerprint()}, lastKey)
						if err == nil {
							mw.modifiedKeys <- lastKey
						}
					} else {
						mw.l.Print("Update: skipped, no change in cumulative digest")
					}
				} else if err == KeyNotFound {
					mw.l.Print("Insert:", key.Fingerprint())
					key.Ctime = time.Now().UnixNano()
					key.Mtime = key.Ctime
					key.CumlDigest = CumlDigest(key)
					err = mw.keys.Insert(key)
					if err == nil {
						mw.createdKeys <- key
					}
				}
				if err != nil {
					mw.l.Print("Error:", err)
					return
				}
				fps = append(fps, key.Fingerprint())
			}
			if !moreKeys {
				return
			}
		case err, ok := <-errChan:
			if ok {
				mw.l.Print(err)
			}
		}
	}
	panic("unreachable")
}

func (mw *MgoWorker) updateStats() {
	keysCreatedDaily := make(map[int64]int)
	keysCreatedHourly := make(map[int64]int)
	keysModifiedDaily := make(map[int64]int)
	keysModifiedHourly := make(map[int64]int)
	flushedAt := time.Now()
	for {
		select {
		case key := <-mw.createdKeys:
			keysCreatedDaily[key.Ctime-(key.Ctime%int64(24*time.Hour))]++
			keysCreatedHourly[key.Ctime-(key.Ctime%int64(time.Hour))]++
		case key := <-mw.modifiedKeys:
			keysModifiedDaily[key.Ctime-(key.Mtime%int64(24*time.Hour))]++
			keysModifiedHourly[key.Ctime-(key.Mtime%int64(time.Hour))]++
		}
		if time.Since(flushedAt) > time.Minute {
			updateStat(mw.keysDaily, keysCreatedDaily, "created")
			updateStat(mw.keysHourly, keysCreatedHourly, "created")
			updateStat(mw.keysDaily, keysModifiedDaily, "modified")
			updateStat(mw.keysHourly, keysModifiedHourly, "modified")
			flushedAt = time.Now()
		}
	}
}

func updateStat(c *mgo.Collection, stats map[int64]int, field string) {
	for timestamp, count := range stats {
		c.Upsert(bson.M{"timestamp": timestamp},
			bson.M{"$inc": bson.M{field: count}})
		delete(stats, timestamp)
	}
}

func (mw *MgoWorker) Status() (status *ServerStatus, err error) {
	status = &ServerStatus{Timestamp: time.Now().UnixNano(),
		PksPeers: lastPksStatus, Version: Version}
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
