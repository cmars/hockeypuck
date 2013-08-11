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

package openpgp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/cmars/conflux"
	"github.com/cmars/conflux/recon"
	"github.com/cmars/conflux/recon/pqptree"
	"github.com/jmoiron/sqlx"
	"io"
	"launchpad.net/hockeypuck/hkp"
	"log"
	"net"
	"net/http"
)

type SksPeer struct {
	*recon.Peer
	Service    *hkp.Service
	KeyChanges KeyChangeChan
}

func NewSksPeer(s *hkp.Service) (*SksPeer, error) {
	reconSettings := recon.NewSettings(Config().Settings.TomlTree)
	pqpTreeSettings := pqptree.NewSettings(reconSettings)
	db, err := sqlx.Connect(Config().Driver(), Config().DSN())
	ptree, err := pqptree.New("sks", db, pqpTreeSettings)
	if err != nil {
		return nil, err
	}
	peer := recon.NewPeer(reconSettings, ptree)
	sksPeer := &SksPeer{Peer: peer, Service: s, KeyChanges: make(KeyChangeChan)}
	return sksPeer, nil
}

func (r *SksPeer) Start() {
	go r.HandleRecovery()
	go r.HandleKeyUpdates()
	go r.Peer.Start()
}

func (r *SksPeer) HandleKeyUpdates() {
	for {
		select {
		case keyChange, ok := <-r.KeyChanges:
			if !ok {
				return
			}
			digest, err := hex.DecodeString(keyChange.CurrentMd5)
			if err != nil {
				log.Println("bad digest:", keyChange.CurrentMd5)
				continue
			}
			digestZp := conflux.Zb(conflux.P_SKS, conflux.ReverseBytes(digest))
			hasDigest, err := r.Peer.HasElement(digestZp)
			if keyChange.PreviousMd5 != keyChange.CurrentMd5 || !hasDigest {
				log.Println("Prefix tree: Insert:", digestZp, keyChange, keyChange.CurrentMd5)
				err := r.Peer.Insert(digestZp)
				if err != nil {
					log.Println(err)
					continue
				}
				if keyChange.PreviousMd5 != "" && keyChange.PreviousMd5 != keyChange.CurrentMd5 {
					prevDigest, err := hex.DecodeString(keyChange.PreviousMd5)
					if err != nil {
						log.Println("bad digest:", keyChange.PreviousMd5)
						continue
					}
					prevDigestZp := conflux.Zb(conflux.P_SKS, conflux.ReverseBytes(prevDigest))
					log.Println("Prefix Tree: Remove:", prevDigestZp)
					err = r.Peer.Remove(prevDigestZp)
					if err != nil {
						log.Println(err)
						continue
					}
				}
			}
		}
	}
}

func (r *SksPeer) HandleRecovery() {
	for {
		select {
		case rcvr, ok := <-r.Peer.RecoverChan:
			if !ok {
				return
			}
			if err := r.requestRecovery(rcvr); err != nil {
				log.Println("Recovery request failed: ", err)
			} else {
				log.Println("Recovery complete")
			}
		}
	}
}

func (r *SksPeer) requestRecovery(rcvr *recon.Recover) (err error) {
	var host string
	host, _, err = net.SplitHostPort(rcvr.RemoteAddr.String())
	if err != nil {
		log.Println("Cannot parse remote address:", err)
		return
	}
	httpPort := rcvr.RemoteConfig.HttpPort
	// Make an sks hashquery request
	hqBuf := bytes.NewBuffer(nil)
	err = recon.WriteInt(hqBuf, len(rcvr.RemoteElements))
	if err != nil {
		return
	}
	for _, z := range rcvr.RemoteElements {
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
		keyBuf := bytes.NewBuffer(nil)
		_, err = io.CopyN(keyBuf, resp.Body, int64(keyLen))
		if err != nil {
			return
		}
		log.Println("Key#", i+1, ":", keyLen, "bytes")
		// Merge locally
		recoverKey := hkp.NewRecoverKey()
		recoverKey.Keytext = keyBuf.Bytes()
		recoverKey.Source = rcvr.RemoteAddr.String()
		go func() {
			r.Service.Requests <- recoverKey
			defer close(recoverKey.Response())
			resp := <-recoverKey.Response()
			if resp.Error() != nil {
				log.Println("Error adding key:", resp.Error())
			}
		}()
	}
	// Read last two bytes (CRLF, why?), or SKS will complain.
	resp.Body.Read(make([]byte, 2))
	return
}

func (r *SksPeer) Stop() {
	r.Peer.Stop()
}
