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

type AggregateKeyStatus struct {
	Timestamp     time.Time
	TotalCreated  int
	TotalModified int
}

type ServerStatus struct {
	Timestamp       string
	Hostname        string
	Port            int
	Version         string
	PksPeers        []PksStat
	TotalKeys       int
	DailyHistogram  []AggregateKeyStatus
	HourlyHistogram []AggregateKeyStatus
}
