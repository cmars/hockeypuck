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
	"launchpad.net/gnuflag"

	. "github.com/hockeypuck/hockeypuck"
	"github.com/hockeypuck/hockeypuck/openpgp"
)

type dbCmd struct {
	configuredCmd
	crTables      bool
	drConstraints bool
	dedup         bool
	crConstraints bool
}

func (c *dbCmd) Name() string { return "db" }

func (c *dbCmd) Desc() string {
	return "OpenPGP database maintenance operations"
}

func newDbCmd() *dbCmd {
	cmd := new(dbCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "Hockeypuck configuration file")
	flags.BoolVar(&cmd.crTables, "create-tables", true, "Create tables if they don't exist")
	flags.BoolVar(&cmd.drConstraints, "drop-constraints", false,
		"Drop all primary key, unique and foreign key constraints")
	flags.BoolVar(&cmd.dedup, "dedup", false, "De-duplicate primary key and unique constraint columns")
	flags.BoolVar(&cmd.crConstraints, "create-constraints", false,
		"Create primary key, unique and foreign key constraints")
	cmd.flags = flags
	return cmd
}

func (c *dbCmd) Main() {
	c.configuredCmd.Main()
	InitLog()
	var db *openpgp.DB
	var err error
	if db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if c.crTables {
		if err = db.CreateTables(); err != nil {
			die(err)
		}
	}
	// Drop constraints
	if c.drConstraints {
		// Create all constraints
		if err = db.DropConstraints(); err != nil {
			die(err)
		}
	}
	// De-duplication option
	if c.dedup {
		if err = db.DeleteDuplicates(); err != nil {
			die(err)
		}
	}
	// Create all constraints
	if c.crConstraints {
		if err = db.CreateConstraints(); err != nil {
			die(err)
		}
	}
}
