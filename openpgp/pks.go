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
	"log"
	"net/smtp"
	"strings"
	"time"
)

// Max delay backoff multiplier when smtp errors
const MAX_DELAY = 60

// PKS mail from address
func (s *Settings) PksFrom() string {
	return s.GetString("hockeypuck.openpgp.pks.from")
}

// Downstream PKS servers
func (s *Settings) PksTo() []string {
	return s.GetStrings("hockeypuck.openpgp.pks.to")
}

// SMTP settings
func (s *Settings) SmtpHost() string {
	return s.GetStringDefault("hockeypuck.openpgp.pks.smtp.host", "localhost:25")
}

func (s *Settings) SmtpId() string {
	return s.GetString("hockeypuck.openpgp.pks.smtp.id")
}

func (s *Settings) SmtpUser() string {
	return s.GetString("hockeypuck.openpgp.pks.smtp.user")
}

func (s *Settings) SmtpPass() string {
	return s.GetString("hockeypuck.openpgp.pks.smtp.pass")
}

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
	// stop channel, used to shut down
	stop chan interface{}
}

// Initialize from command line switches if fields not set.
func NewPksSync(w *Worker) (*PksSync, error) {
	ps := &PksSync{Worker: w, stop: make(chan interface{})}
	ps.MailFrom = Config().PksFrom()
	ps.SmtpHost = Config().SmtpHost()
	authHost := ps.SmtpHost
	if parts := strings.Split(authHost, ":"); len(parts) >= 1 {
		// Strip off the port, use only the hostname for auth
		authHost = parts[0]
	}
	ps.SmtpAuth = smtp.PlainAuth(Config().SmtpId(),
		Config().SmtpUser(), Config().SmtpPass(), authHost)
	ps.PksAddrs = Config().PksTo()
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
		log.Println("Sending key", key.Fingerprint(), "to PKS", status.Addr)
		err = ps.SendKey(status.Addr, key)
		if err != nil {
			log.Println("Error sending key to PKS", status.Addr, ":", err)
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
func (ps *PksSync) run() {
	delay := 1
	for {
		statuses, err := ps.SyncStatus()
		if err != nil {
			log.Println("Error obtaining PKS sync status", err)
			goto POLL_NEXT
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
	POLL_NEXT:
		// Check for stop
		select {
		case _, ok := <-ps.stop:
			if !ok {
				log.Println("Stopping PKS sync")
				return
			}
		default:
			// Nothing on channels, fall thru
		}
		toSleep := time.Duration(delay) * time.Minute
		if delay > 1 {
			// log delay if we had an error
			log.Println("Sleeping", toSleep)
		}
		time.Sleep(toSleep)
	}
}

// Start PKS synchronization
func (ps *PksSync) Start() {
	go ps.run()
}

func (ps *PksSync) Stop() {
	if ps.stop != nil {
		close(ps.stop)
		ps.stop = nil
	}
}
