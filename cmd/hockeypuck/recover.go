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
	"log"

	. "github.com/hockeypuck/hockeypuck"
	"github.com/hockeypuck/hockeypuck/openpgp"
	"launchpad.net/gnuflag"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

type recoverCmd struct {
	configuredCmd
}

func (rc *recoverCmd) Name() string { return "recover" }

func (rc *recoverCmd) Desc() string { return "Recover prefix tree" }

func newRecoverCmd() *recoverCmd {
	cmd := new(recoverCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "Hockeypuck configuration file")
	cmd.flags = flags
	return cmd
}

func (ec *recoverCmd) Main() {
	ec.configuredCmd.Main()
	InitLog()
	path := openpgp.Config().Settings.TomlTree.Get("conflux.recon.leveldb.path").(string)
	stor, err := storage.OpenFile(path)
	if err != nil {
		die(err)
	}
	log.Println("database storage opened, recovering...")
	db, err := leveldb.Recover(stor, nil)
	if err != nil {
		die(err)
	}
	log.Println("recovery complete")
	db.Close()
}
