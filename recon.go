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
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/cmars/conflux"
	"github.com/cmars/conflux/recon"
	"github.com/cmars/conflux/recon/leveldb"
	"io"
	"log"
	"net"
	"net/http"
)

type SksRecon struct {
	*recon.Peer
	Hkp          *HkpServer
	loadedKeys   chan []*LoadKeyStatus
	stopUpdates  chan interface{}
	stopRecovery chan interface{}
}

var ReconNotEnabled error = errors.New("Reconciliation peer not enabled.")
var ReconNotConfigured error = errors.New("Reconciliation peer not configured.")

// Enable SKS reconciliation protocol with conflux
func init() { flag.Bool("recon.enabled", true, "Enable SKS reconciliation protocol") }
func (s *Settings) ReconEnabled() bool {
	return s.GetBool("recon.enabled")
}

func NewSksRecon(hkp *HkpServer) (*SksRecon, error) {
	if !Config().ReconEnabled() {
		return nil, ReconNotEnabled
	}
	settings := leveldb.NewSettings(config.TomlTree)
	peer, err := leveldb.NewPeer(settings)
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
			if err = rp.requestRecovery(host, httpPort, r.RemoteElements); err != nil {
				log.Println("Recovery request failed: ", err)
			} else {
				log.Println("Recovery complete")
			}
		case <-rp.stopRecovery:
			return
		}
	}
}

func (rp *SksRecon) requestRecovery(host string, httpPort int, recoverList []*conflux.Zp) (err error) {
	// Make an sks hashquery request
	hqBuf := bytes.NewBuffer(nil)
	err = recon.WriteInt(hqBuf, len(recoverList))
	if err != nil {
		return
	}
	for _, z := range recoverList {
		zb := conflux.ReverseBytes(z.Bytes())
		err = recon.WriteInt(hqBuf, len(zb))
		if err != nil {
			return
		}
		_, err = hqBuf.Write(zb)
		if err != nil {
			return
		}
	}
	resp, err := http.Post(fmt.Sprintf("http://%s:%d/pks/hashquery", host, httpPort),
		"sks/hashquery", bytes.NewReader(hqBuf.Bytes()))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var nkeys, keyLen int
	nkeys, err = recon.ReadInt(resp.Body)
	if err != nil {
		return
	}
	log.Println("Response from server:", nkeys, " keys found")
	for i := 0; i < nkeys; i++ {
		keyLen, err = recon.ReadInt(resp.Body)
		if err != nil {
			return
		}
		log.Println("Key#", i+1, ":", keyLen, "bytes")
		armorBuf := bytes.NewBuffer(nil)
		var armorOut io.WriteCloser
		if armorOut, err = armor.Encode(armorBuf, openpgp.PublicKeyType, nil); err != nil {
			return
		}
		if _, err = io.CopyN(armorOut, resp.Body, int64(keyLen)); err != nil {
			return
		}
		if err = armorOut.Close(); err != nil {
			return
		}
		respChan := make(ResponseChan)
		go func() {
			defer close(respChan)
			resp := <-respChan
			if resp.Error() != nil {
				log.Println("Error adding key:", resp.Error())
			} else {
				log.Println("Key added")
			}
		}()
		// Merge locally
		rp.Hkp.AddRequests <- &Add{
			responseChan: respChan,
			Keytext:      armorBuf.String(),
			Option:       NoOption}
	}
	// Read last two bytes (CRLF, why?), or SKS will complain.
	resp.Body.Read(make([]byte, 2))
	return
}

func (rp *SksRecon) Stop() {
	rp.stopUpdates <- nil
	rp.stopRecovery <- nil
	rp.Peer.Stop()
}
