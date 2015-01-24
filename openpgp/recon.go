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
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/errgo.v1"
	cf "gopkg.in/hockeypuck/conflux.v2"
	"gopkg.in/hockeypuck/conflux.v2/recon"
	"gopkg.in/hockeypuck/conflux.v2/recon/leveldb"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/tomb.v2"

	"github.com/hockeypuck/hockeypuck"
	"github.com/hockeypuck/hockeypuck/hkp"
)

const RequestChunkSize = 100

const MaxKeyRecoveryAttempts = 3

type KeyRecoveryCounter map[string]int

type SksPeer struct {
	*recon.Peer
	settings   *hockeypuck.Settings
	ptree      recon.PrefixTree
	Service    *hkp.Service
	RecoverKey chan RecoverKey
	KeyChanges KeyChangeChan

	recoverAttempts KeyRecoveryCounter

	t tomb.Tomb
}

type RecoverKey struct {
	Keytext  []byte
	Source   string
	response hkp.ResponseChan
}

func NewSksPTree(s *hockeypuck.Settings) (recon.PrefixTree, error) {
	if _, err := os.Stat(s.Conflux.Recon.LevelDB.Path); os.IsNotExist(err) {
		log.Debugf("creating prefix tree at: %q", s.Conflux.Recon.LevelDB.Path)
		err = os.MkdirAll(s.Conflux.Recon.LevelDB.Path, 0755)
		if err != nil {
			return nil, errgo.Mask(err)
		}
	}
	return leveldb.New(s.Conflux.Recon.PTreeConfig, s.Conflux.Recon.LevelDB.Path)
}

func NewSksPeer(srv *hkp.Service, s *hockeypuck.Settings) (*SksPeer, error) {
	ptree, err := NewSksPTree(s)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	err = ptree.Create()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	peer := recon.NewPeer(&s.Conflux.Recon.Settings, ptree)
	sksPeer := &SksPeer{
		ptree:      ptree,
		settings:   s,
		Peer:       peer,
		Service:    srv,
		KeyChanges: make(KeyChangeChan, s.OpenPGP.NWorkers*4),
		RecoverKey: make(chan RecoverKey, s.OpenPGP.NWorkers*4),

		recoverAttempts: make(KeyRecoveryCounter),
	}
	return sksPeer, nil
}

func (r *SksPeer) Start() {
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	r.t.Go(func() error {
		defer signal.Stop(sigChan)
		defer func() {
			err := r.ptree.Close()
			if err != nil {
				log.Warnf("error closing prefix tree: %v", err)
			}
		}()
		select {
		case <-r.t.Dying():
			return nil
		case sig := <-sigChan:
			log.Infof("caught signal: %v", sig)
			return nil
		}
	})

	r.t.Go(r.HandleRecovery)
	r.t.Go(r.HandleKeyUpdates)
	r.Peer.Start()
}

func (r *SksPeer) Stop() {
	log.Info("recon processing: stopping")
	r.t.Kill(nil)
	err := r.t.Wait()
	if err != nil {
		log.Error(errgo.Details(err))
	}
	log.Info("recon processing: stopped")
	log.Info("recon peer: stopping")
	err = errgo.Mask(r.Peer.Stop())
	if err != nil {
		log.Error(errgo.Details(err))
	}
	log.Info("recon peer: stopped")
}

func DigestZp(digest string) (*cf.Zp, error) {
	buf, err := hex.DecodeString(digest)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	buf = recon.PadSksElement(buf)
	return cf.Zb(cf.P_SKS, buf), nil
}

func (r *SksPeer) HandleKeyUpdates() error {
	for {
		select {
		case <-r.t.Dying():
			return nil
		case keyChange, ok := <-r.KeyChanges:
			if !ok {
				return nil
			}
			digestZp, err := DigestZp(keyChange.CurrentMd5)
			if err != nil {
				log.Warnf("bad digest:", keyChange.CurrentMd5)
				continue
			}
			log.Debugf("insert prefix tree: %q %v %v", hex.EncodeToString(digestZp.Bytes()), keyChange, keyChange.CurrentMd5)
			r.Peer.InsertWith(func(err error) {
				if err != nil {
					log.Errorf("insert %q failed: %v", digestZp, err)
				}
				// TODO: this needs locking!
				delete(r.recoverAttempts, digestZp.String())
			}, digestZp)
			if keyChange.PreviousMd5 != "" && keyChange.PreviousMd5 != keyChange.CurrentMd5 {
				prevDigestZp, err := DigestZp(keyChange.PreviousMd5)
				if err != nil {
					log.Warnf("bad digest:", keyChange.PreviousMd5)
					continue
				}
				log.Debugf("remove prefix tree: %q", prevDigestZp)
				// TODO: here as well
				r.Peer.RemoveWith(func(err error) {
					if err != nil {
						log.Errorf("remove %q failed: %v", prevDigestZp, err)
					}
				}, prevDigestZp)
			}
		}
	}
}

func (r *SksPeer) HandleRecovery() error {
	rcvrChans := make(map[string]chan *recon.Recover)
	defer func() {
		for _, ch := range rcvrChans {
			close(ch)
		}
	}()
	for {
		select {
		case <-r.t.Dying():
			return nil
		case rcvr, ok := <-r.Peer.RecoverChan:
			if !ok {
				return nil
			}
			// Use remote HKP host:port as peer-unique identifier
			remoteAddr, err := rcvr.HkpAddr()
			if err != nil {
				continue
			}
			// Mux recoveries to per-address channels
			rcvrChan, has := rcvrChans[remoteAddr]
			if !has {
				rcvrChan = make(chan *recon.Recover)
				rcvrChans[remoteAddr] = rcvrChan
				go r.handleRemoteRecovery(rcvr, rcvrChan)
			}
			rcvrChan <- rcvr
		}
	}
}

type workRecoveredReady chan interface{}
type workRecoveredWork chan *cf.ZSet

func (r *SksPeer) handleRemoteRecovery(rcvr *recon.Recover, rcvrChan chan *recon.Recover) {
	recovered := cf.NewZSet()
	ready := make(workRecoveredReady)
	work := make(workRecoveredWork)
	defer close(work)
	go r.workRecovered(rcvr, ready, work)
	for {
		select {
		case <-r.t.Dying():
			return
		case rcvr, ok := <-rcvrChan:
			if !ok {
				return
			}
			// Aggregate recovered IDs
			recovered.AddSlice(rcvr.RemoteElements)
			log.Debugf("recovery from %q: %d keys pending", rcvr.RemoteAddr.String(), recovered.Len())
			r.Peer.Disable()
		case _, ok := <-ready:
			// Recovery worker is ready for more
			if !ok {
				return
			}
			work <- recovered
			recovered = cf.NewZSet()
		}
	}
}

func (r *SksPeer) workRecovered(rcvr *recon.Recover, ready workRecoveredReady, work workRecoveredWork) {
	defer close(ready)
	timer := time.NewTimer(time.Duration(3) * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-r.t.Dying():
			return
		case recovered, ok := <-work:
			go func() {
				defer r.Peer.Enable()
				if !ok {
					return
				}
				err := r.requestRecovered(rcvr, recovered)
				if err != nil {
					log.Warn(err)
				}
				timer.Reset(time.Duration(r.settings.Conflux.Recon.GossipIntervalSecs) * time.Second)
			}()
		case <-timer.C:
			timer.Stop()
			ready <- new(interface{})
		}
	}
}

func (r *SksPeer) requestRecovered(rcvr *recon.Recover, elements *cf.ZSet) error {
	items := elements.Items()
	var resultErr error
	for len(items) > 0 {
		// Chunk requests to keep the hashquery message size and peer load reasonable.
		chunksize := RequestChunkSize
		if chunksize > len(items) {
			chunksize = len(items)
		}
		chunk := items[:chunksize]
		items = items[chunksize:]
		r.countChunk(chunk)
		err := r.requestChunk(rcvr, chunk)
		if err != nil {
			if resultErr == nil {
				resultErr = errgo.Mask(err)
			} else {
				resultErr = errgo.Notef(resultErr, "%s", errgo.Details(err))
			}
		}
	}
	return resultErr
}

func (r *SksPeer) countChunk(chunk []*cf.Zp) {
	for _, z := range chunk {
		// TODO: needs locking
		r.recoverAttempts[z.String()] = r.recoverAttempts[z.String()] + 1
		n := r.recoverAttempts[z.String()]
		if n > MaxKeyRecoveryAttempts {
			log.Warnf("giving up on key %q after failing to recover %d attempts", z, n)
			r.InsertWith(func(err error) {
				if err != nil {
					log.Errorf("failed to insert %s into prefix tree to prevent further attempts", z)
				}
			}, z)
		}
	}
}

func (r *SksPeer) requestChunk(rcvr *recon.Recover, chunk []*cf.Zp) error {
	var remoteAddr string
	remoteAddr, err := rcvr.HkpAddr()
	if err != nil {
		return errgo.Mask(err)
	}
	// Make an sks hashquery request
	hqBuf := bytes.NewBuffer(nil)
	err = recon.WriteInt(hqBuf, len(chunk))
	if err != nil {
		return errgo.Mask(err)
	}
	for _, z := range chunk {
		zb := z.Bytes()
		zb = recon.PadSksElement(zb)
		// Hashquery elements are 16 bytes (length_of(P_SKS)-1)
		zb = zb[:len(zb)-1]
		err = recon.WriteInt(hqBuf, len(zb))
		if err != nil {
			return errgo.Mask(err)
		}
		_, err = hqBuf.Write(zb)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	resp, err := http.Post(fmt.Sprintf("http://%s/pks/hashquery", remoteAddr),
		"sks/hashquery", bytes.NewReader(hqBuf.Bytes()))
	if err != nil {
		return errgo.Mask(err)
	}
	// Store response in memory. Connection may timeout if we
	// read directly from it while loading.
	var body *bytes.Buffer
	{
		defer resp.Body.Close()
		bodyBuf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errgo.Mask(err)
		}
		body = bytes.NewBuffer(bodyBuf)
	}
	var nkeys, keyLen int
	nkeys, err = recon.ReadInt(body)
	if err != nil {
		return errgo.Mask(err)
	}
	log.Debugf("hashquery response from %q: %d keys found", remoteAddr, nkeys)
	for i := 0; i < nkeys; i++ {
		keyLen, err = recon.ReadInt(body)
		if err != nil {
			return errgo.Mask(err)
		}
		keyBuf := bytes.NewBuffer(nil)
		_, err = io.CopyN(keyBuf, body, int64(keyLen))
		if err != nil {
			return errgo.Mask(err)
		}
		log.Debugf("key# %d: %d bytes", i+1, keyLen)
		// Merge locally
		recoverKey := RecoverKey{
			Keytext:  keyBuf.Bytes(),
			Source:   rcvr.RemoteAddr.String(),
			response: make(chan hkp.Response)}
		go func() {
			r.RecoverKey <- recoverKey
		}()
		resp := <-recoverKey.response
		if resp, ok := resp.(*RecoverKeyResponse); ok {
			if resp.Error() != nil {
				log.Warnf("failed to add key: %v", resp.Error())
			}
		} else if resp != nil {
			log.Warnf("failed to add key: %v", resp.Error())
		} else {
			log.Warnf("empty response when attempting to recover key")
		}
	}
	// Read last two bytes (CRLF, why?), or SKS will complain.
	body.Read(make([]byte, 2))
	return nil
}
