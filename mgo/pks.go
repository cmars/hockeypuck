/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012, 2013  Casey Marshall

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

var lastPksStatus []PksStatus

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
	_, err = mps.pksStatus.RemoveAll(bson.M{"addr": bson.M{"$not": bson.M{"$in": mps.PksAddrs}}})
	if err != nil {
		return
	}
	// Add pks in this list not in collection
	for _, pksAddr := range mps.PksAddrs {
		err = mps.pksStatus.Insert(&PksStatus{Addr: pksAddr, LastSync: time.Now().UnixNano()})
		if err != nil && !mgo.IsDup(err) {
			return
		} else {
			err = nil
		}
	}
	return
}

func (mps *MgoPksSync) SyncStatus() (status []PksStatus, err error) {
	i := mps.pksStatus.Find(nil).Limit(256).Iter()
	err = i.All(&status)
	lastPksStatus = status
	return
}

func (mps *MgoPksSync) SendKeys(status *PksStatus) (err error) {
	q := mps.keys.Find(bson.M{"mtime": bson.M{"$gt": status.LastSync}})
	i := q.Iter()
	key := &PubKey{}
	for i.Next(key) {
		// Send key email
		log.Println("Sending key", key.Fingerprint(), "to PKS", status.Addr)
		err = mps.SendKey(status.Addr, key)
		if err != nil {
			log.Println("Error sending key to PKS", status.Addr, ":", err)
			return
		}
		// Send successful, update the timestamp accordingly
		status.LastSync = key.Mtime
		err = mps.pksStatus.Update(bson.M{"addr": status.Addr}, status)
		if err != nil {
			log.Println("Error updating PKS status for", status.Addr, err)
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
