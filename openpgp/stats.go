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

package openpgp

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/hockeypuck/hockeypuck/hkp"
)

func (w *Worker) Stats(l *hkp.Lookup) {
	resp := &StatsResponse{Lookup: l, Stats: &HkpStats{Worker: w}}
	resp.Stats.fetchServerInfo(l)
	err := resp.Stats.fetchKeyStats()
	if err != nil {
		l.Response() <- &ErrorResponse{err}
		return
	}
	err = resp.Stats.fetchTotalKeys()
	if err != nil {
		l.Response() <- &ErrorResponse{err}
		return
	}
	l.Response() <- resp
}

type PksKeyStats struct {
	Timestamp time.Time `db:"start"`
	Created   int       `db:"created"`
	Modified  int       `db:"modified"`
}

func (s *PksKeyStats) Day() string {
	return s.Timestamp.Format("2006-01-02 MST")
}

func (s *PksKeyStats) Hour() string {
	return s.Timestamp.Format("2006-01-02 15:04 MST")
}

type HkpStats struct {
	*Worker
	Timestamp      time.Time
	Hostname       string
	Port           int
	Version        string
	PksPeers       []PksStatus
	TotalKeys      int `db:"total_keys"`
	KeyStatsHourly []PksKeyStats
	KeyStatsDaily  []PksKeyStats
}

func (s *HkpStats) fetchServerInfo(l *hkp.Lookup) {
	s.Timestamp = time.Now()
	if host, port, err := net.SplitHostPort(l.Host); err == nil {
		s.Hostname = host
		if s.Port, err = strconv.Atoi(port); err != nil {
			log.Println("Error parsing port:", err)
		}
	} else {
		s.Hostname = l.Host
		log.Println("Error parsing Host:", err)
	}
}

var selectHourlyStats string = `
SELECT SUM(created) AS created, SUM(modified) AS modified, hour AS start
FROM (
	SELECT COUNT(*) AS created, 0 AS modified, date_trunc('hour', ctime) AS hour
	FROM (
		SELECT uuid, ctime FROM openpgp_pubkey WHERE ctime > date_trunc('day', now() - interval '1 day'))
		AS created
	GROUP BY hour
	UNION
	SELECT 0 AS created, COUNT(*) AS modified, date_trunc('hour', mtime) AS hour
	FROM (
		SELECT uuid, mtime FROM openpgp_pubkey WHERE mtime > date_trunc('day', now() - interval '1 day')
			AND mtime != ctime)
		AS modified
	GROUP BY hour) as hourly
GROUP BY hour ORDER BY start DESC`

var selectDailyStats string = `
SELECT SUM(created) AS created, SUM(modified) AS modified, day AS start
FROM (
	SELECT COUNT(*) AS created, 0 AS modified, date_trunc('day', ctime) AS day
	FROM (
		SELECT uuid, ctime FROM openpgp_pubkey WHERE ctime > date_trunc('week', now() - interval '1 week'))
		AS created
	GROUP BY day
	UNION
	SELECT 0 AS created, COUNT(*) AS modified, date_trunc('day', mtime) AS day
	FROM (
		SELECT uuid, mtime FROM openpgp_pubkey WHERE mtime > date_trunc('week', now() - interval '1 week')
			AND mtime != ctime)
		AS modified
	GROUP BY day) as daily
GROUP BY day ORDER BY start DESC`

func (s *HkpStats) fetchKeyStats() (err error) {
	err = s.db.Select(&s.KeyStatsHourly, selectHourlyStats)
	if err != nil {
		return
	}
	err = s.db.Select(&s.KeyStatsDaily, selectDailyStats)
	return
}

func (s *HkpStats) fetchTotalKeys() (err error) {
	return s.db.Get(s, `
SELECT CAST(reltuples AS INTEGER) AS total_keys FROM pg_class WHERE relname = 'openpgp_pubkey'`)
}
