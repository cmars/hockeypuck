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
	"log"
	"regexp"
	"strings"
	"time"
	"unicode"
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
	var keyword string
	if strings.IndexFunc(search, func(c rune) bool { return unicode.IsSpace(c) }) == -1 {
		// No space in search, just lowercase it
		keyword = strings.ToLower(search)
	} else {
		// Try user id splitting
		keywords := SplitUserId(search)
		switch len(keywords) {
		case 0:
			// Couldn't even make sense of it...
			log.Println("Invalid search term:", search)
			err = KeyNotFound
			return
		case 1:
			// We have a name.
			keyword = keywords[0]
		default:
			// Prefer the email address.
			keyword = keywords[1]
		}
	}
	if len(keyword) < 3 {
		// My database has better things to do...
		log.Println("Rejected short search terms:", search)
		err = TooManyResponses
		return
	}
	q := mw.keys.Find(bson.M{"identities.keywords": bson.RegEx{
		Pattern: fmt.Sprintf("^%s", regexp.QuoteMeta(keyword))}})
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
		var regex = bson.RegEx{Pattern: fmt.Sprintf("^%s", rkeyid)}
		q = mw.keys.Find(bson.M{"$or": []bson.M{bson.M{"rfingerprint": regex}, bson.M{"subkeys.rfingerprint": regex}}})
	case 20:
		q = mw.keys.Find(bson.M{"$or": []bson.M{bson.M{"rfingerprint": rkeyid}, bson.M{"subkeys.rfingerprint": rkeyid}}})
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
	defer FinishTraversal(pktChan)
	go func() {
		key.Traverse(pktChan)
		close(pktChan)
	}()
	for pktObj := range pktChan {
		if sig, is := pktObj.(*Signature); is {
			if sig.IssuerUid == "" {
				result := &struct{ Identities []*struct{ Id string } }{}
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
	defer func() {
		for _ = range keyChan {
		}
	}()
	defer func() {
		for _ = range errChan {
		}
	}()
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
						log.Println("Updated:", key.Fingerprint())
						lastKey.Mtime = time.Now().UnixNano()
						err = mw.keys.Update(bson.M{"rfingerprint": key.RFingerprint}, lastKey)
						if err == nil {
							mw.modifiedKeys <- lastKey
						}
					} else {
						log.Println("Update: skipped, no change in cumulative digest")
					}
				} else if err == KeyNotFound {
					log.Println("Insert:", key.Fingerprint())
					key.Ctime = time.Now().UnixNano()
					key.Mtime = key.Ctime
					key.CumlDigest = CumlDigest(key)
					err = mw.keys.Insert(key)
					if err == nil {
						mw.createdKeys <- key
					}
				}
				if err != nil {
					log.Println("Error:", err)
					return
				}
				fps = append(fps, key.Fingerprint())
			}
			if !moreKeys {
				return
			}
		case readErr, ok := <-errChan:
			if ok {
				log.Println(readErr)
			} else {
				return
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
			keysModifiedDaily[key.Mtime-(key.Mtime%int64(24*time.Hour))]++
			keysModifiedHourly[key.Mtime-(key.Mtime%int64(time.Hour))]++
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

func (mw *MgoWorker) Stats() (stats *ServerStats, err error) {
	stats = &ServerStats{Timestamp: time.Now().UnixNano(),
		PksPeers: lastPksStatus, Version: Version}
	for keyStat := range mw.KeyStatsHourly() {
		stats.KeyStatsHourly = append(stats.KeyStatsHourly, keyStat)
	}
	for keyStat := range mw.KeyStatsDaily() {
		stats.KeyStatsDaily = append(stats.KeyStatsDaily, keyStat)
	}
	stats.TotalKeys, err = mw.keys.Count()
	if err != nil {
		return
	}
	return
}
