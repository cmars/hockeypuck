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
var PksFrom *string = flag.String("pks-from", "", "PKS sync mail from: address")

// Downstream PKS servers
var PksTo *string = flag.String("pks-to", "", "Send keys to these PKS servers")

// SMTP settings
var SmtpHost *string = flag.String("smtp-host", "", "SMTP Hostname")
var SmtpId *string = flag.String("smtp-id", "", "SMTP Account ID")
var SmtpUser *string = flag.String("smtp-user", "", "SMTP Account Username")
var SmtpPass *string = flag.String("smtp-pass", "", "SMTP Account Password")

// Status of PKS synchronization
type PksStat struct {
	// Email address of the PKS server.
	Addr string
	// Timestamp of the last sync to this server.
	LastSync int64
}

// PKS synchronization operations.
// Implemented over a specific storage backend.
type PksSync interface {
	// Get PKS sync status
	SyncStats() ([]PksStat, error)
	// Send updated keys to PKS server
	SendKeys(stat *PksStat) error
}

// Handle used to control PKS synchronization once started
type PksSyncHandle struct {
	pksSync PksSync
	stop    chan interface{}
	l       *log.Logger
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
		ps.MailFrom = *PksFrom
	}
	if ps.SmtpHost == "" {
		ps.SmtpHost = *SmtpHost
	}
	authHost := ps.SmtpHost
	if parts := strings.Split(authHost, ":"); len(parts) >= 1 {
		// Strip off the port, use only the hostname for auth
		authHost = parts[0]
	}
	if ps.SmtpAuth == nil {
		ps.SmtpAuth = smtp.PlainAuth(*SmtpId, *SmtpUser, *SmtpPass, authHost)
	}
	if len(ps.PksAddrs) == 0 && len(*PksTo) > 0 {
		ps.PksAddrs = strings.Split(*PksTo, ",")
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
			stats, err := psh.pksSync.SyncStats()
			if err != nil {
				psh.l.Println("Error obtaining PKS sync stats", err)
				goto POLL_NEXT
			}
			for _, stat := range stats {
				err = psh.pksSync.SendKeys(&stat)
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
					psh.l.Println("Stopping PKS sync")
					return
				}
			default:
				// Nothing on channels, fall thru

			}
			toSleep := time.Duration(delay) * time.Minute
			if delay > 1 {
				// log delay if we had an error
				psh.l.Println("Sleeping", toSleep)
			}
			time.Sleep(toSleep)
		}
	}()
}

// Start PKS synchronization
func StartPksSync(pksSync PksSync) *PksSyncHandle {
	psh := &PksSyncHandle{pksSync: pksSync, stop: make(chan interface{})}
	EnsureLog(&psh.l)
	pollPks(psh)
	return psh
}
