/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

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

// hockeypuck is an OpenPGP keyserver.
package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/conflux.v2"
	"gopkg.in/hockeypuck/conflux.v2/recon"
	log "gopkg.in/hockeypuck/logrus.v0"
	"launchpad.net/gnuflag"

	"github.com/hockeypuck/hockeypuck/openpgp"
)

type pbuildCmd struct {
	configuredCmd
	cache      int
	ignoreDups bool

	readErr error
}

func (c *pbuildCmd) Name() string { return "pbuild" }

func (c *pbuildCmd) Desc() string {
	return "Build reconciliation prefix tree from public keys in database"
}

func newPbuildCmd() *pbuildCmd {
	cmd := new(pbuildCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "Hockeypuck configuration file")
	flags.IntVar(&cmd.cache, "cache", 64, "Max diskv cache size (MB)")
	flags.BoolVar(&cmd.ignoreDups, "ignore-dups", false, "Ignore duplicate entries")
	cmd.flags = flags
	return cmd
}

func (c *pbuildCmd) Main() error {
	if c.cache <= 0 {
		return newUsageError(c, "Max cache size must be > 0")
	}
	err := c.configuredCmd.Main()
	if err != nil {
		return errgo.Mask(err)
	}

	db, err := openpgp.NewDB(c.settings)
	if err != nil {
		return errgo.Mask(err)
	}

	ptree, err := openpgp.NewSksPTree(c.settings)
	if err != nil {
		return errgo.NoteMask(err, "failed to instantiate prefix tree")
	}
	err = ptree.Create()
	if err != nil {
		return errgo.NoteMask(err, "failed to create/open prefix tree")
	}
	n := 0
	for z := range c.readHashes(db) {
		err = ptree.Insert(z)
		if err != nil {
			if c.ignoreDups && strings.Contains(err.Error(), "insert duplicate element") {
				continue
			}
			log.Errorf("failed to insert %x into ptree: %v", z.Bytes(), err)
			return errgo.Mask(err)
		}
		n++
		if n%1000 == 0 {
			fmt.Printf(".")
		}
	}
	if c.readErr != nil {
		return errgo.Mask(c.readErr)
	}
	return errgo.NoteMask(ptree.Close(), "error closing prefix tree")
}

func (c *pbuildCmd) readHashes(db *openpgp.DB) chan *conflux.Zp {
	hashes := make(chan *conflux.Zp)
	go func() {
		defer close(hashes)
		rows, err := db.DB.Query("SELECT md5 FROM openpgp_pubkey")
		if err != nil {
			c.readErr = errgo.NoteMask(err, "db select error")
			return
		}
		for rows.Next() {
			var md5str string
			err = rows.Scan(&md5str)
			if err != nil {
				c.readErr = errgo.Mask(err)
				return
			}
			digest, err := hex.DecodeString(md5str)
			if err != nil {
				log.Warnf("bad key md5 %q found in query", md5str)
				continue
			}
			digest = recon.PadSksElement(digest)
			digestZp := conflux.Zb(conflux.P_SKS, digest)
			hashes <- digestZp
		}
		err = rows.Err()
		if err != nil {
			c.readErr = errgo.NoteMask(err, "db error during hash query")
			return
		}
	}()
	return hashes
}
