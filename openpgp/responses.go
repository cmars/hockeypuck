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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/cmars/conflux/recon"

	"launchpad.net/hockeypuck"
	. "launchpad.net/hockeypuck/errors"
	"launchpad.net/hockeypuck/hkp"
)

type ErrorResponse struct {
	Err error
}

func (r *ErrorResponse) Error() error {
	return r.Err
}

func (r *ErrorResponse) WriteTo(w http.ResponseWriter) error {
	w.WriteHeader(400)
	fmt.Fprintf(w, hockeypuck.BAD_REQUEST)
	log.Println(r.Err)
	return r.Err
}

type MessageResponse struct {
	Content []byte
	Err     error
}

func (r *MessageResponse) Error() error {
	return r.Err
}

func (r *MessageResponse) WriteTo(w http.ResponseWriter) error {
	w.Write([]byte(r.Content))
	return r.Err
}

type AddResponse struct {
	Changes []*KeyChange
	Errors  []*ReadKeyResult
}

func (r *AddResponse) Error() error {
	if len(r.Changes) > 0 || len(r.Errors) == 0 {
		return nil
	}
	return errors.New("One or more keys had an error")
}

func (r *AddResponse) WriteTo(w http.ResponseWriter) (err error) {
	if hkp.AddResultTemplate == nil {
		return ErrTemplatePathNotFound
	}
	err = hkp.AddResultTemplate.ExecuteTemplate(w, "top", r)
	if err != nil {
		return
	}
	err = hkp.AddResultTemplate.ExecuteTemplate(w, "page_content", r)
	if err != nil {
		return
	}
	err = hkp.AddResultTemplate.ExecuteTemplate(w, "bottom", r)
	return
}

type RecoverKeyResponse struct {
	Change *KeyChange
	Err    error
}

func (r *RecoverKeyResponse) Error() error {
	return r.Err
}

func (r *RecoverKeyResponse) WriteTo(w http.ResponseWriter) error {
	if r.Err != nil {
		return r.Err
	}
	fmt.Fprintf(w, "%v", r.Change)
	return nil
}

type StatsResponse struct {
	Lookup *hkp.Lookup
	Stats  *HkpStats
	Err    error
}

func (r *StatsResponse) Error() error {
	return r.Err
}

func (r *StatsResponse) WriteTo(w http.ResponseWriter) (err error) {
	err = r.Err
	if err != nil {
		return
	}
	if r.Lookup.Option&(hkp.JsonFormat|hkp.MachineReadable) != 0 {
		// JSON is the only supported machine readable stats format.
		w.Header().Add("Content-Type", "application/json")
		msg := map[string]interface{}{
			"timestamp": r.Stats.Timestamp,
			"hostname":  r.Stats.Hostname,
			"http_port": r.Stats.Port,
			"numkeys":   r.Stats.TotalKeys,
			"software":  filepath.Base(os.Args[0]),
			"version":   r.Stats.Version}
		// Convert hourly stats
		hours := []interface{}{}
		for _, hour := range r.Stats.KeyStatsHourly {
			hours = append(hours, map[string]interface{}{
				"time":         hour.Timestamp.Unix(),
				"new_keys":     hour.Created,
				"updated_keys": hour.Modified})
		}
		msg["stats_by_hour"] = hours
		// Convert daily stats
		days := []interface{}{}
		for _, day := range r.Stats.KeyStatsDaily {
			days = append(days, map[string]interface{}{
				"time":         day.Timestamp.Unix(),
				"new_keys":     day.Created,
				"updated_keys": day.Modified})
		}
		msg["stats_by_day"] = days
		// Convert mailsync stats
		mailPeers := []string{}
		for _, pksStat := range r.Stats.PksPeers {
			mailPeers = append(mailPeers, pksStat.Addr)
		}
		msg["mailsync_peers"] = mailPeers
		// Serialize and send
		var jsonStr []byte
		jsonStr, err = json.Marshal(msg)
		if err == nil {
			fmt.Fprintf(w, "%s", jsonStr)
		}
	} else {
		w.Header().Add("Content-Type", "text/html")
		if hkp.StatsTemplate == nil {
			return ErrTemplatePathNotFound
		}
		err = hkp.StatsTemplate.ExecuteTemplate(w, "layout", r.Stats)
	}
	return
}

type KeyringResponse struct {
	Keys []*Pubkey
}

func (k *KeyringResponse) Error() error {
	return nil
}

func (k *KeyringResponse) WriteTo(w http.ResponseWriter) error {
	for _, key := range k.Keys {
		err := WriteArmoredPackets(w, key)
		if err != nil {
			return err
		}
	}
	return nil
}

type HashQueryResponse struct {
	Keys []*Pubkey
}

func (hq *HashQueryResponse) Error() error {
	return nil
}

func (hq *HashQueryResponse) WriteTo(w http.ResponseWriter) (err error) {
	w.Header().Set("Content-Type", "pgp/keys")
	// Write the number of keys
	err = recon.WriteInt(w, len(hq.Keys))
	for _, key := range hq.Keys {
		// Write each key in binary packet format, prefixed with length
		keybuf := bytes.NewBuffer(nil)
		err = WritePackets(keybuf, key)
		if err != nil {
			return
		}
		err = recon.WriteInt(w, keybuf.Len())
		if err != nil {
			return
		}
		_, err = w.Write(keybuf.Bytes())
		if err != nil {
			return
		}
	}
	// SKS expects hashquery response to terminate with a CRLF
	_, err = w.Write([]byte{0x0d, 0x0a})
	return
}

type NotImplementedResponse struct {
}

func (e *NotImplementedResponse) Error() error {
	return errors.New("Not implemented")
}

func (e *NotImplementedResponse) WriteTo(w http.ResponseWriter) error {
	w.WriteHeader(400)
	return e.Error()
}
