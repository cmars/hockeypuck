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

package hockeypuck

import (
	"bytes"
	"flag"
	"github.com/cmars/conflux/recon"
	"log"
	"runtime"
	"strings"
)

const FIND_KEYS_LIMIT = 10
const INDEX_LIMIT = 50

// Number of workers to spawn
func init() { flag.Int("workers", runtime.NumCPU(), "Number of workers") }
func (s *Settings) NumWorkers() int {
	return s.GetInt("workers")
}

type Worker interface {
	// Look up keys by search string. Prefix with 0x will look up key id,
	// other strings match on tokenized user ID.
	LookupKeys(search string, limit int) ([]*PubKey, error)
	// Look up a key by ID.
	LookupKey(keyid string) (*PubKey, error)
	// Look up a key by hash.
	LookupHash(hash string) (*PubKey, error)
	// Add ASCII-armored public key
	AddKey(armoredKey string) ([]*LoadKeyStatus, error)
	// Get server stats
	Stats() (*ServerStats, error)
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

type LoadKeyStatus struct {
	// Public key fingerprint of the loaded keyring
	Fingerprint string
	// Latest digest of the merged key
	Digest string
	// Prior digest before merged, or empty string if new inserted key.
	LastDigest string
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
						armor, err = FindKeys(wh.w, strings.ToLower(lookup.Search))
					}
					lookup.Response() <- &MessageResponse{Content: []byte(armor), Err: err}
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
				case Stats:
					stats, err := wh.w.Stats()
					stats.Hostname = lookup.Hostname
					stats.Port = lookup.Port
					lookup.Response() <- &StatsResponse{Stats: stats, Err: err, Lookup: lookup}
				case HashGet:
					out := bytes.NewBuffer(nil)
					key, err := wh.w.LookupHash(lookup.Search)
					if err == nil {
						err = WriteKey(out, key)
					}
					lookup.Response() <- &MessageResponse{Content: out.Bytes(), Err: err}
				case HashQuery:
					out := bytes.NewBuffer(nil)
					hashes := strings.Split(lookup.Search, ",")
					var key *PubKey
					var err error
					err = recon.WriteInt(out, len(hashes))
					for _, hash := range hashes {
						key, err = wh.w.LookupHash(hash)
						if err != nil {
							log.Println("hashquery: error looking up hash", hash, ":", err)
							break
						}
						keyOut := bytes.NewBuffer(nil)
						pktObjChan := make(chan PacketObject)
						go func() {
							key.Traverse(pktObjChan)
							close(pktObjChan)
						}()
						for pktObj := range pktObjChan {
							_, err = keyOut.Write(pktObj.GetPacket())
							if err != nil {
								log.Println("hashquery: error writing key for hash", hash)
								break
							}
						}
						FinishTraversal(pktObjChan)
						err = recon.WriteInt(out, keyOut.Len())
						if err != nil {
							log.Println("hashquery: error writing key length for hash", hash)
							break
						}
						_, err = out.Write(keyOut.Bytes())
						if err != nil {
							log.Println("hashquery: error writing key contents for hash", hash)
							break
						}
						log.Println("hashquery: wrote hash", hash)
					}
					// SKS expects hashquery response to terminate with a CRLF
					out.Write([]byte{0x0d, 0x0a})
					lookup.Response() <- &MessageResponse{Content: out.Bytes(), Err: err}
				default:
					lookup.Response() <- &NotImplementedResponse{}
				}
			case add := <-wh.hkp.AddRequests:
				statuses, err := wh.w.AddKey(add.Keytext)
				if wh.hkp.recon != nil {
					wh.hkp.recon.loadedKeys <- statuses
				}
				add.Response() <- &AddResponse{Statuses: statuses, Err: err}
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
