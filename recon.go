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
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/cmars/conflux"
	"github.com/cmars/conflux/recon"
	"github.com/cmars/conflux/recon/leveldb"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

var reconDir *string = flag.String("recon-db", "/var/lib/hockeypuck/recon.db", "Recon database path")
var reconCfg *string = flag.String("recon-conf", "/etc/hockeypuck/recon.conf", "Recon configuration file")

type SksRecon struct {
	*recon.Peer
	Hkp          *HkpServer
	loadedKeys   chan []*LoadKeyStatus
	stopUpdates  chan interface{}
	stopRecovery chan interface{}
}

var ReconNotConfigured error = errors.New("Reconciliation peer not configured.")

func NewSksRecon(hkp *HkpServer) (*SksRecon, error) {
	var settings *recon.Settings
	if *reconCfg != "" {
		settings = recon.LoadSettings(*reconCfg)
	} else {
		return nil, ReconNotConfigured
	}
	if *reconDir == "" {
		return nil, ReconNotConfigured
	}
	peer, err := leveldb.NewPeer(*reconDir, settings)
	if err != nil {
		return nil, err
	}
	hkp.recon = &SksRecon{peer, hkp, make(chan []*LoadKeyStatus),
		make(chan interface{}), make(chan interface{})}
	return hkp.recon, nil
}

func (rp *SksRecon) Start() {
	go rp.HandleRecovery()
	go rp.HandleKeyUpdates()
	go rp.Peer.Start()
}

func (rp *SksRecon) HandleKeyUpdates() {
	for {
		select {
		case statuses, ok := <-rp.loadedKeys:
			if !ok {
				return
			}
			for _, status := range statuses {
				digest, err := hex.DecodeString(status.Digest)
				if err != nil {
					log.Println("bad digest:", status.Digest)
					continue
				}
				digestZp := conflux.Zb(conflux.P_SKS, conflux.ReverseBytes(digest))
				log.Println("Insert digest: ", digestZp)
				rp.Peer.Insert(digestZp)
				if status.LastDigest != "" && status.LastDigest != status.Digest {
					lastDigest, err := hex.DecodeString(status.LastDigest)
					if err != nil {
						log.Println("bad digest:", status.LastDigest)
						continue
					}
					lastDigestZp := conflux.Zb(conflux.P_SKS, conflux.ReverseBytes(lastDigest))
					rp.Peer.Remove(lastDigestZp)
					log.Println("Remove digest: ", lastDigestZp)
				}
			}
		case <-rp.stopUpdates:
			return
		}
	}
}

func (rp *SksRecon) HandleRecovery() {
	for {
		select {
		case r, ok := <-rp.Peer.RecoverChan:
			if !ok {
				return
			}
			host, _, err := net.SplitHostPort(r.RemoteAddr.String())
			if err != nil {
				log.Println("Cannot parse remote address:", err)
				continue
			}
			httpPort := r.RemoteConfig.HttpPort
			for _, z := range r.RemoteElements {
				// hget from remote addr (need http address)
				url := fmt.Sprintf("http://%s:%s/pks/lookup?op=hget&search=%s",
					host, httpPort, z)
				resp, err := http.Get(url)
				if err != nil {
					log.Println(host, ": HGet request failed:", err)
					continue
				}
				defer resp.Body.Close()
				keytext, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Println("Error reading HGet response:", err)
					continue
				}
				// Merge locally
				rp.Hkp.AddRequests <- &Add{
					Keytext: string(keytext),
					Option:  NoOption}
			}
		case <-rp.stopRecovery:
			return
		}
	}
}

func (rp *SksRecon) Stop() {
	rp.stopUpdates <- nil
	rp.stopRecovery <- nil
	rp.Peer.Stop()
}
