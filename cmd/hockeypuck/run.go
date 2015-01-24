package main

import (
	"net/http"
	"path/filepath"

	"github.com/gorilla/mux"
	"gopkg.in/errgo.v1"
	"gopkg.in/tomb.v2"
	"launchpad.net/gnuflag"

	"github.com/hockeypuck/hockeypuck"
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

func (c *runCmd) Main() error {
	err := c.configuredCmd.Main()
	if err != nil {
		return errgo.Mask(err)
	}

	// Create an HTTP request router
	r := mux.NewRouter()
	// Add common static routes
	hockeypuck.NewStaticRouter(r, c.settings)
	// Create HKP router
	hkpRouter := hkp.NewRouter(r)
	// Create SKS peer
	sksPeer, err := openpgp.NewSksPeer(hkpRouter.Service, c.settings)
	if err != nil {
		return errgo.Mask(err)
	}
	// Launch the OpenPGP workers
	for i := 0; i < c.settings.OpenPGP.NWorkers; i++ {
		w, err := openpgp.NewWorker(hkpRouter.Service, sksPeer)
		if err != nil {
			return errgo.Mask(err)
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
	if c.settings.Hkps != nil && c.settings.Hkps.Bind != "" {
		if c.settings.Hkps.Cert == "" {
			return errgo.New("missing TLS certificate")
		} else if c.settings.Hkps.Key == "" {
			return errgo.New("missing TLS private key")
		}

		if filepath.IsAbs(c.settings.Hkps.Cert) {
			tlsCertPath = c.settings.Hkps.Cert
		} else {
			tlsCertPath = filepath.Join(c.configDir, c.settings.Hkps.Cert)
		}

		if filepath.IsAbs(c.settings.Hkps.Key) {
			tlsKeyPath = c.settings.Hkps.Key
		} else {
			tlsKeyPath = filepath.Join(c.configDir, c.settings.Hkps.Key)
		}
		hkpsConfigured = true
	}

	var t tomb.Tomb

	if c.settings.Hkp.Bind != "" {
		t.Go(func() error {
			return http.ListenAndServe(c.settings.Hkp.Bind, nil)
		})
	}
	if hkpsConfigured {
		t.Go(func() error {
			return http.ListenAndServeTLS(c.settings.Hkps.Bind,
				tlsCertPath, tlsKeyPath, nil)
		})
	}

	return t.Wait()
}
