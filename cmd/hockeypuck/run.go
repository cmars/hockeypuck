package main

import (
	"fmt"
	"net/http"
	"path/filepath"

	"code.google.com/p/gorilla/mux"
	"launchpad.net/gnuflag"

	. "github.com/hockeypuck/hockeypuck"
	"github.com/hockeypuck/hockeypuck/hkp"
	"github.com/hockeypuck/hockeypuck/openpgp"
)

type runCmd struct {
	configuredCmd
}

func (c *runCmd) Name() string { return "run" }

func (c *runCmd) Desc() string { return "Run Hockeypuck services" }

func newRunCmd() *runCmd {
	cmd := &runCmd{}
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "Hockeypuck configuration file")
	cmd.flags = flags
	return cmd
}

func (c *runCmd) Main() {
	c.configuredCmd.Main()
	InitLog()
	// Create an HTTP request router
	r := mux.NewRouter()
	// Add common static routes
	NewStaticRouter(r)
	// Create HKP router
	hkpRouter := hkp.NewRouter(r)
	// Create SKS peer
	sksPeer, err := openpgp.NewSksPeer(hkpRouter.Service)
	if err != nil {
		die(err)
	}
	// Launch the OpenPGP workers
	for i := 0; i < openpgp.Config().NumWorkers(); i++ {
		w, err := openpgp.NewWorker(hkpRouter.Service, sksPeer)
		if err != nil {
			die(err)
		}
		// Subscribe SKS to worker's key changes
		w.SubKeyChanges(sksPeer.KeyChanges)
		go w.Run()
	}
	sksPeer.Start()
	// Bind the router to the built-in webserver root
	http.Handle("/", r)

	var hkpsConfigured bool
	var tlsCertPath, tlsKeyPath string
	if hkp.Config().HttpsBind() != "" {
		if hkp.Config().TLSCertificate() == "" {
			err = fmt.Errorf("no TLS certificate provided")
		} else if hkp.Config().TLSKey() == "" {
			err = fmt.Errorf("no TLS private key provided")
		}

		if err != nil {
			die(err)
		}

		if filepath.IsAbs(hkp.Config().TLSCertificate()) {
			tlsCertPath = hkp.Config().TLSCertificate()
		} else {
			tlsCertPath = filepath.Join(c.configDir, hkp.Config().TLSCertificate())
		}

		if filepath.IsAbs(hkp.Config().TLSKey()) {
			tlsKeyPath = hkp.Config().TLSKey()
		} else {
			tlsKeyPath = filepath.Join(c.configDir, hkp.Config().TLSKey())
		}
		hkpsConfigured = true
	}

	if hkpsConfigured {
		if hkp.Config().HttpBind() != "" {
			go func() {
				// Start the built-in webserver, run forever
				err = http.ListenAndServe(hkp.Config().HttpBind(), nil)
				die(err)
			}()
		}
		err = http.ListenAndServeTLS(hkp.Config().HttpsBind(),
			tlsCertPath, tlsKeyPath, nil)
		die(err)
	} else {
		// Start the built-in webserver, run forever
		err = http.ListenAndServe(hkp.Config().HttpBind(), nil)
		die(err)
	}
}
