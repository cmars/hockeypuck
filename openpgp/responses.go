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
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/conflux.v2/recon"
	log "gopkg.in/hockeypuck/logrus.v0"

	. "github.com/hockeypuck/hockeypuck/errors"
	"github.com/hockeypuck/hockeypuck/hkp"
)

type ErrorResponse struct {
	Err error
}

func (r *ErrorResponse) Error() error {
	return r.Err
}

func (r *ErrorResponse) WriteTo(w http.ResponseWriter) error {
	w.WriteHeader(http.StatusBadRequest)
	//fmt.Fprintf(w, hockeypuck.BAD_REQUEST)
	log.Error(r.Err)
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
	return errgo.New("failed to add one or more keys")
}

func (r *AddResponse) WriteTo(w http.ResponseWriter) error {
	if hkp.AddResultTemplate == nil {
		return ErrTemplatePathNotFound
	}
	err := hkp.AddResultTemplate.ExecuteTemplate(w, "top", r)
	if err != nil {
		return err
	}
	if err = hkp.AddResultTemplate.ExecuteTemplate(w, "page_content", r); err != nil {
		return err
	}
	if err = hkp.AddResultTemplate.ExecuteTemplate(w, "bottom", r); err != nil {
		return err
	}
	return nil
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

func (r *StatsResponse) WriteTo(w http.ResponseWriter) error {
	err := r.Err
	if err != nil {
		return err
	}
	if r.Stats.NotReady() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, err = fmt.Fprintf(w, "statistics not ready")
		return err
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
			//"version":   hockeypuck.Version}
		}
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
	return nil
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

func (hq *HashQueryResponse) WriteTo(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "pgp/keys")
	// Write the number of keys
	err := recon.WriteInt(w, len(hq.Keys))
	for _, key := range hq.Keys {
		// Write each key in binary packet format, prefixed with length
		keybuf := bytes.NewBuffer(nil)
		if err = WritePackets(keybuf, key); err != nil {
			return err
		}
		if err = recon.WriteInt(w, keybuf.Len()); err != nil {
			return err
		}
		if _, err = w.Write(keybuf.Bytes()); err != nil {
			return err
		}
	}
	// SKS expects hashquery response to terminate with a CRLF
	if _, err = w.Write([]byte{0x0d, 0x0a}); err != nil {
		return err
	}
	return nil
}

type NotImplementedResponse struct {
}

func (e *NotImplementedResponse) Error() error {
	return errgo.New("not implemented")
}

func (e *NotImplementedResponse) WriteTo(w http.ResponseWriter) error {
	w.WriteHeader(400)
	return e.Error()
}
