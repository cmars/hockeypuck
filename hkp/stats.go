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
	"net"
	"strconv"
	"sync"
	"time"

	"gopkg.in/errgo.v1"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/tomb.v2"

	"github.com/hockeypuck/hockeypuck/hkp"
)

var (
	keyStatsLock   *sync.Mutex
	keyStatsHourly []PksKeyStats
	keyStatsDaily  []PksKeyStats
	keyStatsTotal  int
)

func init() {
	keyStatsLock = &sync.Mutex{}
}

func (w *Worker) monitorStats() error {
	statsRefresh := w.settings.OpenPGP.StatsRefreshHours
	if statsRefresh <= 0 {
		log.Infof("load statistics disabled")
		<-w.t.Dying()
		return nil
	}

	timer := time.NewTimer(time.Duration(statsRefresh) * time.Hour)
	for {
		select {
		case <-w.t.Dying():
			return nil
		case <-timer.C:
			var t tomb.Tomb
			t.Go(func() error {
				var stats []struct {
					TotalKeys int `db:"total_keys"`
				}
				err := w.db.Select(&stats, selectTotalKeys)
				if err != nil {
					log.Errorf("failed to update total keys: %v", err)
					return errgo.Mask(err)
				}
				keyStatsLock.Lock()
				defer keyStatsLock.Unlock()
				if len(stats) > 0 {
					keyStatsTotal = stats[0].TotalKeys
					log.Info("total keys updated")
				}
				return nil
			})
			t.Go(func() error {
				var stats []PksKeyStats
				err := w.db.Select(&stats, selectHourlyStats)
				if err != nil {
					log.Errorf("failed to update hourly stats: %v", err)
					return errgo.Mask(err)
				}
				keyStatsLock.Lock()
				defer keyStatsLock.Unlock()
				keyStatsHourly = stats
				log.Info("hourly stats updated")
				return nil
			})
			t.Go(func() error {
				var stats []PksKeyStats
				err := w.db.Select(&stats, selectDailyStats)
				if err != nil {
					log.Errorf("failed to update daily stats: %v", err)
					return errgo.Mask(err)
				}
				keyStatsLock.Lock()
				defer keyStatsLock.Unlock()
				keyStatsDaily = stats
				log.Info("daily stats updated")
				return nil
			})
			select {
			case <-w.t.Dying():
				return nil
			case <-t.Dead():
				err := t.Err()
				if err != nil {
					log.Errorf("error updating stats: %v", errgo.Details(err))
				}
			}
			timer.Reset(time.Duration(statsRefresh) * time.Hour)
		}
	}
}

func (w *Worker) Stats(l *hkp.Lookup) {
	keyStatsLock.Lock()
	defer keyStatsLock.Unlock()
	resp := &StatsResponse{
		Lookup: l,
		Stats: &HkpStats{
			//Version:        hockeypuck.Version,
			KeyStatsHourly: keyStatsHourly,
			KeyStatsDaily:  keyStatsDaily,
			TotalKeys:      keyStatsTotal,
		},
	}
	resp.Stats.fetchServerInfo(l)
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
	Timestamp      time.Time
	Hostname       string
	Port           int
	Version        string
	PksPeers       []PksStatus
	TotalKeys      int
	KeyStatsHourly []PksKeyStats
	KeyStatsDaily  []PksKeyStats
}

func (s *HkpStats) NotReady() bool {
	return s.TotalKeys == 0
}

func (s *HkpStats) fetchServerInfo(l *hkp.Lookup) {
	s.Timestamp = time.Now()
	if host, port, err := net.SplitHostPort(l.Host); err == nil {
		s.Hostname = host
		if s.Port, err = strconv.Atoi(port); err != nil {
			log.Warnf("cannot parse port out of address %q: %v", l.Host, err)
		}
	} else {
		s.Hostname = l.Host
		log.Warnf("cannot parse address %q: %v", l.Host, err)
	}
}

var selectTotalKeys string = `SELECT COUNT(1) AS total_keys FROM openpgp_pubkey`

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
