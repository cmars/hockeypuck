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
	"github.com/cmars/conflux"
	"github.com/cmars/conflux/recon"
	"launchpad.net/gnuflag"
	. "launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/openpgp"
	"log"
)

type deleteCmd struct {
	configuredCmd
	keyHash string
}

func (ec *deleteCmd) Name() string { return "delete" }

func (ec *deleteCmd) Desc() string { return "Delete key hash from prefix tree" }

func newDeleteCmd() *deleteCmd {
	cmd := new(deleteCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "Hockeypuck configuration file")
	flags.StringVar(&cmd.keyHash, "keyHash", "", "Delete key hash")
	cmd.flags = flags
	return cmd
}

func (ec *deleteCmd) Main() {
	if ec.keyHash == "" {
		Usage(ec, "--keyHash is required")
	}
	keyHash, err := hex.DecodeString(ec.keyHash)
	if err != nil {
		die(err)
	}
	ec.configuredCmd.Main()
	InitLog()
	var db *openpgp.DB
	if db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(err)
	}
	var ptree recon.PrefixTree
	reconSettings := recon.NewSettings(openpgp.Config().Settings.TomlTree)
	if ptree, err = openpgp.NewSksPTree(reconSettings); err != nil {
		die(err)
	}
	// Create the prefix tree (if not exists)
	if err = ptree.Create(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(err)
	}
	if err = ptree.Remove(conflux.Zb(conflux.P_SKS, keyHash)); err != nil {
		die(err)
	}
	log.Println(ec.keyHash, "deleted from prefix tree")
}
