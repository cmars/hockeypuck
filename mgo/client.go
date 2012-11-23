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
	. "launchpad.net/hockeypuck"
	"log"
)

type MgoClient struct {
	connect string
	l       *log.Logger
	session *mgo.Session
	keys    *mgo.Collection
	pksStat *mgo.Collection
}

func NewMgoClient(connect string) (mc *MgoClient, err error) {
	mc = &MgoClient{connect: connect}
	EnsureLog(&mc.l)
	mc.l.Println("Connecting to mongodb:", mc.connect)
	mc.session, err = mgo.Dial(mc.connect)
	if err != nil {
		mc.l.Println("Connection failed:", err)
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
	return
}

func (mc *MgoClient) initKeys() (err error) {
	// keys collection stores all the key material
	mc.keys = mc.session.DB("hockeypuck").C("keys")
	// fingerprint index
	fpIndex := mgo.Index{
		Key:        []string{"fingerprint"},
		Unique:     true,
		DropDups:   false,
		Background: false,
		Sparse:     false}
	err = mc.keys.EnsureIndex(fpIndex)
	if err != nil {
		mc.l.Println("Ensure index failed:", err)
		return
	}
	// keyid index
	keyidIndex := mgo.Index{
		Key:        []string{"keyid"},
		Unique:     false,
		DropDups:   false,
		Background: false,
		Sparse:     false}
	err = mc.keys.EnsureIndex(keyidIndex)
	if err != nil {
		mc.l.Println("Ensure index failed:", err)
		return
	}
	// shortid index
	shortidIndex := mgo.Index{
		Key:        []string{"shortid"},
		Unique:     false,
		DropDups:   false,
		Background: false,
		Sparse:     false}
	err = mc.keys.EnsureIndex(shortidIndex)
	if err != nil {
		mc.l.Println("Ensure index failed:", err)
		return
	}
	// uid keyword index
	kwIndex := mgo.Index{
		Key:        []string{"identities.keywords"},
		Unique:     false,
		DropDups:   false,
		Background: true,
		Sparse:     false}
	err = mc.keys.EnsureIndex(kwIndex)
	if err != nil {
		mc.l.Println("Ensure index failed:", err)
		return
	}
	return
}

func (mc *MgoClient) initPksSync() (err error) {
	// pks collection stores sync status with downstream servers
	mc.pksStat = mc.session.DB("hockeypuck").C("pksStat")
	// pks addr index
	addrIndex := mgo.Index{
		Key:        []string{"addr"},
		Unique:     true,
		DropDups:   false,
		Background: true,
		Sparse:     false}
	err = mc.pksStat.EnsureIndex(addrIndex)
	if err != nil {
		mc.l.Println("Ensure index failed:", err)
		return
	}
	return
}
