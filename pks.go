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
	"net/smtp"
	"strings"
)

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
	Addr     string
	// Timestamp of the last sync to this server.
	LastSync int64
}

// Outbound PKS synchronization
type PksSender struct {
	// Our PKS email address, which goes into the From: address outbound
	MailFrom string
	// Remote PKS servers we are sending updates to
	PksAddrs []string
	// SMTP host used to send email
	SmtpHost string
	// SMTP authentication
	SmtpAuth smtp.Auth
}

func (ps *PksSender) Init() {
	// Obtain settings from command line switches if fields not set.
	if ps.MailFrom == "" {
		ps.MailFrom = *PksFrom
	}
	if ps.SmtpHost == "" {
		ps.SmtpHost = *SmtpHost
		ps.SmtpAuth = smtp.PlainAuth(*SmtpId, *SmtpUser, *SmtpPass, *SmtpHost)
	}
	if len(ps.PksAddrs) == 0 {
		ps.PksAddrs = strings.Split(*PksTo, ",")
	}
}

// Email an updated public key to a PKS server.
func (ps *PksSender) SendKey(addr string, key *PubKey) (err error) {
	msg := bytes.NewBuffer([]byte{})
	msg.WriteString("Subject: ADD\n\n")
	WriteKey(msg, key)
	err = smtp.SendMail(ps.SmtpHost, ps.SmtpAuth, ps.MailFrom, []string{ addr }, msg.Bytes())
	return
}
