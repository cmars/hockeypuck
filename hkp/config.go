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

// Package hkp implements the OpenPGP HTTP Keyserver Protocol, as
// described in the Internet-Draft, http://ietfreport.isoc.org/idref/draft-shaw-openpgp-hkp/.
//
// hkp provides a few extensions to the protocol, such as
// SKS hashquery, server statistics and JSON-formatted search results.
package hkp

import (
	"launchpad.net/hockeypuck"
)

// Settings stores HKP-specific settings for Hockeypuck.
type Settings struct {
	*hockeypuck.Settings
}

// Config returns the global HKP-specific Settings for Hockeypuck.
func Config() *Settings {
	return &Settings{hockeypuck.Config()}
}
