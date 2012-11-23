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
	"flag"
	"runtime"
	"strings"
)

const FIND_KEYS_LIMIT = 10
const INDEX_LIMIT = 50

// Number of workers to spawn
var NumWorkers *int = flag.Int("workers", runtime.NumCPU(), "Number of workers")

type Worker interface {
	// Look up keys by search string. Prefix with 0x will look up key id,
	// other strings match on tokenized user ID.
	LookupKeys(search string, limit int) ([]*PubKey, error)
	// Look up a key by ID.
	LookupKey(keyid string) (*PubKey, error)
	// Add ASCII-armored public key
	AddKey(armoredKey string) ([]string, error)
}

type WorkerHandle struct {
	w    Worker
	hkp  *HkpServer
	stop chan interface{}
}

func (wh *WorkerHandle) Stop() {
	close(wh.stop)
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

// Serve HKP requests
func serveHkp(wh *WorkerHandle) {
	go func() {
		for {
			select {
			case lookup := <-wh.hkp.LookupRequests:
				switch lookup.Op {
				case Get:
					var armor string
					var err error
					if lookup.Exact || strings.HasPrefix(lookup.Search, "0x") {
						armor, err = GetKey(wh.w, lookup.Search[2:])
					} else {
						armor, err = FindKeys(wh.w, lookup.Search)
					}
					lookup.Response() <- &MessageResponse{Content: armor, Err: err}
				case Index, Vindex:
					var key *PubKey
					var err error
					keys := []*PubKey{}
					if lookup.Exact || strings.HasPrefix(lookup.Search, "0x") {
						key, err = wh.w.LookupKey(lookup.Search[2:])
						keys = append(keys, key)
					} else {
						keys, err = wh.w.LookupKeys(lookup.Search, INDEX_LIMIT)
					}
					lookup.Response() <- &IndexResponse{Keys: keys, Err: err, Lookup: lookup}
				default:
					lookup.Response() <- &NotImplementedResponse{}
				}
			case add := <-wh.hkp.AddRequests:
				fps, err := wh.w.AddKey(add.Keytext)
				add.Response() <- &AddResponse{Fingerprints: fps, Err: err}
			case _, isOpen := <-wh.stop:
				if !isOpen {
					return
				}
			}
		}
	}()
}

func StartWorker(hkp *HkpServer, w Worker) *WorkerHandle {
	wh := &WorkerHandle{w: w, hkp: hkp, stop: make(chan interface{})}
	serveHkp(wh)
	return wh
}
