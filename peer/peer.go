package peer

import (
	"errors"
	"flag"
	"fmt"
	"github.com/cmars/conflux/recon"
	"github.com/cmars/conflux/recon/leveldb"
	"io/ioutil"
	. "launchpad.net/hockeypuck"
	"log"
	"net"
	"net/http"
)

var reconDir *string = flag.String("recon-db", "/var/lib/hockeypuck/recon.db", "Recon database path")
var reconCfg *string = flag.String("recon-conf", "/etc/hockeypuck/recon.conf", "Recon configuration file")

type SksPeer struct {
	*recon.Peer
	Hkp          *HkpServer
	stopRecovery chan interface{}
}

var ReconNotConfigured error = errors.New("Reconciliation peer not configured.")

func NewPeer(hkp *HkpServer) (*SksPeer, error) {
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
	return &SksPeer{peer, hkp, make(chan interface{})}, nil
}

func (rp *SksPeer) Start() {
	go rp.HandleRecovery()
	go rp.Peer.Start()
}

func (rp *SksPeer) HandleRecovery() {
	go func() {
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
	}()
}

func (rp *SksPeer) Stop() {
	rp.stopRecovery <- nil
	rp.Peer.Stop()
}
