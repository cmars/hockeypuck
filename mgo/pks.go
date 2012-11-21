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
	"time"
)

func (mw *MgoWorker) initPksAddrs() (err error) {
	// Remove all pks not in this list
	_, err = mw.pksStat.RemoveAll(bson.M{"$not": bson.M{"addr": bson.M{"$in": mw.PksAddrs}}})
	if err != nil {
		return
	}
	// Add pks in this list not in collection
	for _, pksAddr := range mw.PksAddrs {
		err = mw.pksStat.Insert(bson.M{"addr": pksAddr, "lastSync": time.Now().Unix()})
		if !mgo.IsDup(err) {
			return
		}
	}
	return
}

func (mw *MgoWorker) SyncStats() (stats []PksStat, err error) {
	i := mw.pksStat.Find(nil).Limit(256).Iter()
	err = i.All(&stats)
	return
}

func (mw *MgoWorker) SendKeys(stat *PksStat) (err error) {
	q := mw.keys.Find(bson.M{"Mtime": bson.M{"$gt": stat.LastSync}})
	i := q.Iter()
	key := &PubKey{}
	for i.Next(&key) {
		err = mw.SendKey(stat.Addr, key)
		if err != nil {
			mw.L.Println("Error sending key to PKS", stat.Addr, ":", err)
			return
		}
		key = &PubKey{}
	}
	err = i.Err()
	if err != nil {
		mw.L.Println("Error looking up keys for PKS send:", err)
		return
	}
	err = mw.pksStat.Update(bson.M{"addr": stat.Addr},
		bson.M{"$set": bson.M{"lastSync": time.Now().Unix()}})
	if err != nil {
		mw.L.Println("Error updating PKS", stat.Addr, "sync timestamp:", err)
		return
	}
	return
}
