/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012, 2013  Casey Marshall

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
	"launchpad.net/gnuflag"
	. "launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/openpgp"
)

type dropConstraintsCmd struct {
	configuredCmd
}

func (c *dropConstraintsCmd) Name() string { return "drop-constraints" }

func (c *dropConstraintsCmd) Desc() string {
	return "Drop OpenPGP database constraints for offline bulk load"
}

func newDropConstraintsCmd() *dropConstraintsCmd {
	cmd := new(dropConstraintsCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "Hockeypuck configuration file")
	cmd.flags = flags
	return cmd
}

func (c *dropConstraintsCmd) Main() {
	InitLog()
	var db *openpgp.DB
	var err error
	if db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	// Drop all constraints
	if err = db.DropConstraints(); err != nil {
		die(err)
	}
}
