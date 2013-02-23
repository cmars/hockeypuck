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
	"log"
)

type indexInfo struct {
	name   string
	unique bool
}

var keysIndexes []mgo.Index = []mgo.Index{
	mgo.Index{Key: []string{"rfingerprint"}, Unique: true},
	mgo.Index{Key: []string{"identities.keywords"}}}

var pksStatIndexes []mgo.Index = []mgo.Index{
	mgo.Index{Key: []string{"addr"}, Unique: true}}

type MgoClient struct {
	connect    string
	session    *mgo.Session
	keys       *mgo.Collection
	pksStat    *mgo.Collection
	keysHourly *mgo.Collection
	keysDaily  *mgo.Collection
}

func NewMgoClient(connect string) (mc *MgoClient, err error) {
	mc = &MgoClient{connect: connect}
	log.Println("Connecting to mongodb:", mc.connect)
	mc.session, err = mgo.Dial(mc.connect)
	if err != nil {
		log.Println("Connection failed:", err)
		return
	}
	mc.session.SetMode(mgo.Strong, true)
	// Conservative on writes
	mc.session.EnsureSafe(&mgo.Safe{
		W:     1,
		FSync: true})
	// Initialize collections
	err = mc.initKeys()
	if err != nil {
		return
	}
	err = mc.initPksSync()
	if err != nil {
		return
	}
	err = mc.initUpdateKeys()
	if err != nil {
		return
	}
	return
}

func (mc *MgoClient) initKeys() (err error) {
	// keys collection stores all the key material
	mc.keys = mc.session.DB("hockeypuck").C("keys")
	for _, index := range keysIndexes {
		err = mc.keys.EnsureIndex(index)
		if err != nil {
			log.Println("Ensure index", index.Key, "failed:", err)
			return
		}
	}
	return
}

func (mc *MgoClient) initPksSync() (err error) {
	// pks collection stores sync status with downstream servers
	mc.pksStat = mc.session.DB("hockeypuck").C("pksStat")
	for _, index := range pksStatIndexes {
		err = mc.pksStat.EnsureIndex(index)
		if err != nil {
			log.Println("Ensure index", index.Key, "failed:", err)
			return
		}
	}
	return
}

func (mc *MgoClient) initUpdateKeys() (err error) {
	mc.keysHourly = mc.session.DB("hockeypuck").C("keysHourly")
	err = mc.keysHourly.EnsureIndex(mgo.Index{Key: []string{"timestamp"}, Unique: true})
	if err != nil {
		return
	}
	mc.keysDaily = mc.session.DB("hockeypuck").C("keysDaily")
	err = mc.keysDaily.EnsureIndex(mgo.Index{Key: []string{"timestamp"}, Unique: true})
	return
}
