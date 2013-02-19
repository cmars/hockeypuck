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
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	. "launchpad.net/hockeypuck"
	"log"
	"time"
)

var lastPksStatus []PksStat

type MgoPksSync struct {
	*MgoClient
	PksSyncBase
}

func (mps *MgoPksSync) Init() (err error) {
	mps.PksSyncBase.Init()
	err = mps.initPksAddrs()
	return
}

func (mps *MgoPksSync) initPksAddrs() (err error) {
	// Remove all pks not in this list
	_, err = mps.pksStat.RemoveAll(bson.M{"addr": bson.M{"$not": bson.M{"$in": mps.PksAddrs}}})
	if err != nil {
		return
	}
	// Add pks in this list not in collection
	for _, pksAddr := range mps.PksAddrs {
		err = mps.pksStat.Insert(&PksStat{Addr: pksAddr, LastSync: time.Now().UnixNano()})
		if err != nil && !mgo.IsDup(err) {
			return
		} else {
			err = nil
		}
	}
	return
}

func (mps *MgoPksSync) SyncStats() (stats []PksStat, err error) {
	i := mps.pksStat.Find(nil).Limit(256).Iter()
	err = i.All(&stats)
	lastPksStatus = stats
	return
}

func (mps *MgoPksSync) SendKeys(stat *PksStat) (err error) {
	q := mps.keys.Find(bson.M{"mtime": bson.M{"$gt": stat.LastSync}})
	i := q.Iter()
	key := &PubKey{}
	for i.Next(key) {
		// Send key email
		log.Println("Sending key", key.Fingerprint(), "to PKS", stat.Addr)
		err = mps.SendKey(stat.Addr, key)
		if err != nil {
			log.Println("Error sending key to PKS", stat.Addr, ":", err)
			return
		}
		// Send successful, update the timestamp accordingly
		stat.LastSync = key.Mtime
		err = mps.pksStat.Update(bson.M{"addr": stat.Addr}, stat)
		if err != nil {
			log.Println("Error updating PKS status for", stat.Addr, err)
			return
		}
		key = &PubKey{}
	}
	err = i.Err()
	if err != nil {
		log.Println("Error looking up keys for PKS send:", err)
		return
	}
	return
}
