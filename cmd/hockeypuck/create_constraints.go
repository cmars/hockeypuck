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

type createConstraintsCmd struct {
	configuredCmd
	dedup bool
}

func (c *createConstraintsCmd) Name() string { return "create-constraints" }

func (c *createConstraintsCmd) Desc() string {
	return "Create OpenPGP database constraints for normal operation"
}

func newCreateConstraintsCmd() *createConstraintsCmd {
	cmd := new(createConstraintsCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "Hockeypuck configuration file")
	flags.BoolVar(&cmd.dedup, "dedup", true, "De-duplicate primary key and unique constraint columns before creating constraints")
	cmd.flags = flags
	return cmd
}

func (c *createConstraintsCmd) Main() {
	InitLog()
	var db *openpgp.DB
	var err error
	if db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(err)
	}
	// De-duplication option
	if c.dedup {
		if err = db.DeleteDuplicates(); err != nil {
			die(err)
		}
	}
	// Create all constraints
	if err = db.CreateConstraints(); err != nil {
		die(err)
	}
}
