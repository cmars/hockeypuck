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

package hockeypuck

import (
	"bytes"
	"log"
	"os"
	"strings"
	"time"
)

const FIND_KEYS_LIMIT = 10
const INDEX_LIMIT = 50

type Worker interface {
	// Look up keys by search string. Prefix with 0x will look up key id,
	// other strings match on tokenized user ID.
	LookupKeys(search string, limit int) ([]*PubKey, error)
	// Look up a key by ID.
	LookupKey(keyid string) (*PubKey, error)
	// Add ASCII-armored public key
	AddKey(armoredKey string) ([]string, error)
	// Get PKS sync status
	SyncStats() ([]PksStat, error)
	// Send updated keys to PKS server
	SendKeys(stat *PksStat) error
}

type WorkerBase struct {
	L *log.Logger
}

func (w *WorkerBase) Init() {
	if w.L == nil {
		w.L = log.New(os.Stderr, "[hockeypuck]", log.LstdFlags|log.Lshortfile)
	}
}

func GetKey(w Worker, keyid string) (string, error) {
	//w.L.Print("GetKey(", keyid, ")")
	key, err := w.LookupKey(keyid)
	if err != nil {
		return "", InvalidKeyId
	}
	out := bytes.NewBuffer([]byte{})
	err = WriteKey(out, key)
	//w.L.Println(err)
	return string(out.Bytes()), err
}

func FindKeys(w Worker, search string) (string, error) {
	//w.L.Print("FindKeys(", search, ")")
	keys, err := w.LookupKeys(search, FIND_KEYS_LIMIT)
	if err != nil {
		return "", err
	}
	if len(keys) == 0 {
		return "", KeyNotFound
	}
	//w.L.Print(len(keys), "matches")
	buf := bytes.NewBuffer([]byte{})
	for _, key := range keys {
		err = WriteKey(buf, key)
		if err != nil {
			return "", err
		}
	}
	return string(buf.Bytes()), err
}

func pollPks(w Worker, stop chan interface{}) {
	for {
		time.Sleep(15 * time.Minute)
		stats, err := w.SyncStats()
		if err != nil {
			continue
		}
		for _, stat := range stats {
			err = w.SendKeys(&stat)
		}
		select {
		case _, isOpen := <-stop:
			if !isOpen {
				return
			}
		}
	}
}

func Start(hkp *HkpServer, w Worker) chan interface{} {
	stop := make(chan interface{})
	// Serve HKP requests
	go func() {
		for {
			select {
			case lookup := <-hkp.LookupRequests:
				switch lookup.Op {
				case Get:
					var armor string
					var err error
					if lookup.Exact || strings.HasPrefix(lookup.Search, "0x") {
						armor, err = GetKey(w, lookup.Search[2:])
					} else {
						armor, err = FindKeys(w, lookup.Search)
					}
					lookup.Response() <- &MessageResponse{Content: armor, Err: err}
				case Index, Vindex:
					var key *PubKey
					var err error
					keys := []*PubKey{}
					if lookup.Exact || strings.HasPrefix(lookup.Search, "0x") {
						key, err = w.LookupKey(lookup.Search[2:])
						keys = append(keys, key)
					} else {
						keys, err = w.LookupKeys(lookup.Search, INDEX_LIMIT)
					}
					lookup.Response() <- &IndexResponse{Keys: keys, Err: err, Lookup: lookup}
				default:
					lookup.Response() <- &NotImplementedResponse{}
				}
			case add := <-hkp.AddRequests:
				fps, err := w.AddKey(add.Keytext)
				add.Response() <- &AddResponse{Fingerprints: fps, Err: err}
			case _, isOpen := <-stop:
				if !isOpen {
					return
				}
			}
		}
	}()
	// Poll PKS downstream servers
	go func() {
		pollPks(w, stop)
	}()
	return stop
}
