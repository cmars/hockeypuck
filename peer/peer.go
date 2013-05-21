package peer

import (
	"github.com/cmars/conflux/recon"
	"github.com/cmars/conflux/recon/cask"
	//. "launchpad.net/hockeypuck"
	"errors"
	"flag"
)

var reconDir *string = flag.String("recon-db-path", "/var/lib/hockeypuck/recon-db", "Recon database path")
var reconCfg *string = flag.String("recon-cfg", "/etc/hockeypuck/recon.conf", "Recon configuration file")

type ReconPeer struct {
	peer *recon.Peer
	stop chan interface{}
}

var ReconNotConfigured error = errors.New("Reconciliation peer not configured.")

func NewPeer() (*ReconPeer, error) {
	var settings *recon.Settings
	if *reconCfg != "" {
		settings = recon.LoadSettings(*reconCfg)
	} else {
		return nil, ReconNotConfigured
	}
	if *reconDir != "" {
		return nil, ReconNotConfigured
	}
	peer, err := cask.NewPeer(*reconDir, settings)
	if err != nil {
		return nil, err
	}
	return &ReconPeer{peer, make(chan interface{})}, nil
}

func (rp *ReconPeer) Start() {
	go func() {
		for {
			select {
			case r, ok := <-rp.peer.RecoverChan:
				if !ok {
					return
				}
				for _ /*z*/, _ = range r.RemoteElements {
					// TODO: hget from remote addr (need http address)
					// TODO: Merge locally
				}
			case <-rp.stop:
				return
			}
		}
	}()
}

func (rp *ReconPeer) Stop() {
	rp.stop <- nil
	rp.peer.Stop()
}
