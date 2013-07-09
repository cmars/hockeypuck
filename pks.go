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
	"bytes"
	"flag"
	"log"
	"net/smtp"
	"strings"
	"time"
)

// Max delay backoff multiplier when smtp errors
const MAX_DELAY = 60

// PKS mail from address
func init() { flag.String("pks.from", "", "PKS sync mail from: address") }
func (s *Settings) PksFrom() string {
	return s.GetString("pks.from")
}

// Downstream PKS servers
func init() { flag.String("pks.to", "", "Send keys to these PKS servers") }
func (s *Settings) PksTo() string {
	return s.GetString("pks.to")
}

// SMTP settings
func init() { flag.String("smtp.host", "", "SMTP Hostname") }
func (s *Settings) SmtpHost() string {
	return s.GetString("smtp.host")
}

func init() { flag.String("smtp.id", "", "SMTP Account ID") }
func (s *Settings) SmtpId() string {
	return s.GetString("smtp.id")
}

func init() { flag.String("smtp.user", "", "SMTP Account Username") }
func (s *Settings) SmtpUser() string {
	return s.GetString("smtp.user")
}

func init() { flag.String("smtp.pass", "", "SMTP Account Password") }
func (s *Settings) SmtpPass() string {
	return s.GetString("smtp.pass")
}

// Status of PKS synchronization
type PksStatus struct {
	// Email address of the PKS server.
	Addr string
	// Timestamp of the last sync to this server.
	LastSync int64
}

// PKS synchronization operations.
// Implemented over a specific storage backend.
type PksSync interface {
	// Get PKS sync status
	SyncStatus() ([]PksStatus, error)
	// Send updated keys to PKS server
	SendKeys(stat *PksStatus) error
}

// Handle used to control PKS synchronization once started
type PksSyncHandle struct {
	pksSync PksSync
	stop    chan interface{}
}

// Stop a running PKS synchronization poll
func (psh *PksSyncHandle) Stop() {
	close(psh.stop)
}

// Basic implementation of outbound PKS synchronization
type PksSyncBase struct {
	// Our PKS email address, which goes into the From: address outbound
	MailFrom string
	// Remote PKS servers we are sending updates to
	PksAddrs []string
	// SMTP host used to send email
	SmtpHost string
	// SMTP authentication
	SmtpAuth smtp.Auth
}

// Initialize from command line switches if fields not set.
func (ps *PksSyncBase) Init() {
	if ps.MailFrom == "" {
		ps.MailFrom = Config().PksFrom()
	}
	if ps.SmtpHost == "" {
		ps.SmtpHost = Config().SmtpHost()
	}
	authHost := ps.SmtpHost
	if parts := strings.Split(authHost, ":"); len(parts) >= 1 {
		// Strip off the port, use only the hostname for auth
		authHost = parts[0]
	}
	if ps.SmtpAuth == nil {
		ps.SmtpAuth = smtp.PlainAuth(Config().SmtpId(), Config().SmtpUser(), Config().SmtpPass(), authHost)
	}
	if len(ps.PksAddrs) == 0 && len(Config().PksTo()) > 0 {
		ps.PksAddrs = strings.Split(Config().PksTo(), ",")
	}
}

// Email an updated public key to a PKS server.
func (ps *PksSyncBase) SendKey(addr string, key *PubKey) (err error) {
	msg := bytes.NewBuffer([]byte{})
	msg.WriteString("Subject: ADD\n\n")
	WriteKey(msg, key)
	err = smtp.SendMail(ps.SmtpHost, ps.SmtpAuth, ps.MailFrom, []string{addr}, msg.Bytes())
	return
}

// Poll PKS downstream servers
func pollPks(psh *PksSyncHandle) {
	go func() {
		delay := 1
		for {
			statuses, err := psh.pksSync.SyncStatus()
			if err != nil {
				log.Println("Error obtaining PKS sync status", err)
				goto POLL_NEXT
			}
			for _, status := range statuses {
				err = psh.pksSync.SendKeys(&status)
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
			case _, isOpen := <-psh.stop:
				if !isOpen {
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
	}()
}

// Start PKS synchronization
func StartPksSync(pksSync PksSync) *PksSyncHandle {
	psh := &PksSyncHandle{pksSync: pksSync, stop: make(chan interface{})}
	pollPks(psh)
	return psh
}
