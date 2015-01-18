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
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"gopkg.in/errgo.v1"
	log "gopkg.in/hockeypuck/logrus.v0"
	"launchpad.net/gnuflag"
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

func (ec *recoverCmd) Main() error {
	err := ec.configuredCmd.Main()
	if err != nil {
		return errgo.Mask(err)
	}

	path := ec.settings.Conflux.Recon.LevelDB.Path
	stor, err := storage.OpenFile(path)
	if err != nil {
		die(err)
	}
	log.Info("database storage opened, recovering...")
	db, err := leveldb.Recover(stor, nil)
	if err != nil {
		return errgo.Mask(err)
	}
	log.Info("recovery complete")
	return errgo.Mask(db.Close())
}
