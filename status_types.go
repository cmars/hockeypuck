/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012  Casey Marshall

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
package hockeypuck

import (
	"time"
)

type KeyOpStats struct {
	Timestamp int64
	Created   int
	Modified  int
}

func (kos *KeyOpStats) Day() string {
	return time.Unix(0, kos.Timestamp).Format("2006-01-02 MST")
}

func (kos *KeyOpStats) Hour() string {
	return time.Unix(0, kos.Timestamp).Format("2006-01-02 15:04 MST")
}

type ServerStatus struct {
	Timestamp      string
	Hostname       string
	Port           int
	Version        string
	PksPeers       []PksStat
	TotalKeys      int
	KeyStatsHourly []*KeyOpStats
	KeyStatsDaily  []*KeyOpStats
}
