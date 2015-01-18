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
	"bytes"
	"net/smtp"
	"strings"
	"time"

	"gopkg.in/errgo.v1"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/tomb.v2"

	"github.com/hockeypuck/hockeypuck/settings"
)

// Max delay backoff multiplier when smtp errors
const MAX_DELAY = 60

// Status of PKS synchronization
type PksStatus struct {
	// Email address of the PKS server.
	Addr string `db:"email_addr"`
	// Timestamp of the last sync to this server.
	LastSync time.Time `db:"last_sync"`
}

// Basic implementation of outbound PKS synchronization
type PksSync struct {
	*Worker
	// Our PKS email address, which goes into the From: address outbound
	MailFrom string
	// Remote PKS servers we are sending updates to
	PksAddrs []string
	// SMTP host used to send email
	SmtpHost string
	// SMTP authentication
	SmtpAuth smtp.Auth
	// Last status
	lastStatus []PksStatus

	t tomb.Tomb
}

// Initialize from command line switches if fields not set.
func NewPksSync(w *Worker, s *settings.Settings) (*PksSync, error) {
	if s.OpenPGP.Pks == nil {
		return nil, errgo.New("PKS mail synchronization not configured")
	}

	ps := &PksSync{Worker: w}
	ps.MailFrom = s.OpenPGP.Pks.From
	ps.SmtpHost = s.OpenPGP.Pks.Smtp.Host
	authHost := ps.SmtpHost
	if parts := strings.Split(authHost, ":"); len(parts) >= 1 {
		// Strip off the port, use only the hostname for auth
		authHost = parts[0]
	}
	ps.SmtpAuth = smtp.PlainAuth(s.OpenPGP.Pks.Smtp.ID,
		s.OpenPGP.Pks.Smtp.User, s.OpenPGP.Pks.Smtp.Password, authHost)
	ps.PksAddrs = s.OpenPGP.Pks.To
	err := ps.initStatus()
	return ps, err
}

func (ps *PksSync) initStatus() error {
	stmt, err := ps.db.Preparex(`
INSERT INTO pks_status (uuid, email_addr)
SELECT $1, $2 WHERE NOT EXISTS (
	SELECT 1 FROM pks_status WHERE email_addr = $2)`)
	if err != nil {
		return err
	}
	for _, emailAddr := range ps.PksAddrs {
		uuid, err := NewUuid()
		if err != nil {
			return err
		}
		_, err = stmt.Exec(uuid, emailAddr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ps *PksSync) SyncStatus() ([]PksStatus, error) {
	var status []PksStatus
	err := ps.db.Select(&status, `
SELECT email_addr, last_sync FROM pks_status
WHERE creation < now() AND expiration > now() AND state = 0`)
	if err != nil {
		return nil, err
	}
	ps.lastStatus = status
	return status, nil
}

func (ps *PksSync) SendKeys(status *PksStatus) error {
	var uuids []string
	err := ps.db.Select(&uuids, "SELECT uuid FROM openpgp_pubkey WHERE mtime > $1",
		status.LastSync)
	if err != nil {
		return err
	}
	keys := ps.fetchKeys(uuids).GoodKeys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		// Send key email
		log.Debugf("sending key %q to PKS %s", key.Fingerprint(), status.Addr)
		err = ps.SendKey(status.Addr, key)
		if err != nil {
			log.Errorf("error sending key to PKS %s: %v", status.Addr, err)
			return err
		}
		// Send successful, update the timestamp accordingly
		status.LastSync = key.Mtime
		_, err = ps.db.Exec("UPDATE pks_status SET last_sync = $1 WHERE email_addr = $2",
			status.LastSync, status.Addr)
		if err != nil {
			return err
		}
	}
	return nil
}

// Email an updated public key to a PKS server.
func (ps *PksSync) SendKey(addr string, key *Pubkey) error {
	msg := bytes.NewBuffer(nil)
	msg.WriteString("Subject: ADD\n\n")
	WriteArmoredPackets(msg, key)
	return smtp.SendMail(ps.SmtpHost, ps.SmtpAuth, ps.MailFrom, []string{addr}, msg.Bytes())
}

// Poll PKS downstream servers
func (ps *PksSync) run() error {
	delay := 1
	timer := time.NewTimer(time.Duration(delay) * time.Minute)
	for {
		select {
		case <-ps.t.Dying():
			return nil
		case <-timer.C:
		}

		statuses, err := ps.SyncStatus()
		if err != nil {
			log.Errorf("failed to obtain PKS sync status: %v", err)
			goto DELAY
		}
		for _, status := range statuses {
			err = ps.SendKeys(&status)
			if err != nil {
				// Increase delay backoff
				delay++
				if delay > MAX_DELAY {
					delay = MAX_DELAY
				}
				break
			} else {
				// Successful mail sent, reset delay
				delay = 1
			}
		}

	DELAY:
		toSleep := time.Duration(delay) * time.Minute
		if delay > 1 {
			// log delay if we had an error
			log.Debugf("PKS sleeping %d minute(s)", toSleep)
		}
		timer.Reset(toSleep)
	}
}

// Start PKS synchronization
func (ps *PksSync) Start() {
	ps.t.Go(ps.run)
}

func (ps *PksSync) Stop() error {
	ps.t.Kill(nil)
	return ps.t.Wait()
}
