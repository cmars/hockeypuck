/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012, 2013  Casey Marshall

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
	"code.google.com/p/go.crypto/openpgp/packet"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cmars/conflux/recon"
	"github.com/qpliu/qrencode-go/qrencode"
	"image/png"
	"io"
	"log"
	"launchpad.net/hockeypuck"
	. "launchpad.net/hockeypuck/errors"
	"launchpad.net/hockeypuck/hkp"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

type IndexResponse struct {
	Lookup  *hkp.Lookup
	Keys    []*Pubkey
	Verbose bool
	Err     error
}

func (r *IndexResponse) Error() error {
	return r.Err
}

func (r *IndexResponse) WriteTo(w http.ResponseWriter) error {
	err := r.Err
	var writeFn func(io.Writer, *Pubkey) error = nil
	if r.Lookup.Option&hkp.MachineReadable != 0 {
		writeFn = r.WriteMachineReadable
	} else {
		writeFn = r.WriteIndex
	}
	if r.Lookup.Option&hkp.MachineReadable != 0 {
		writeFn = r.WriteMachineReadable
		w.Header().Add("Content-Type", "text/plain")
		fmt.Fprintf(w, "info:1:%d\n", len(r.Keys))
	} else {
		if hkp.PksIndexTemplate == nil {
			return ErrTemplatePathNotFound
		}
		w.Header().Add("Content-Type", "text/html")
		err = hkp.PksIndexTemplate.ExecuteTemplate(w, "index-top", r.Lookup.Search)
	}
	if writeFn == nil {
		err = ErrUnsupportedOperation
	}
	if len(r.Keys) == 0 {
		err = ErrKeyNotFound
	}
	if err == nil {
		for _, key := range r.Keys {
			err = writeFn(w, key)
		}
	} else {
		return err
	}
	if r.Lookup.Option&hkp.MachineReadable == 0 {
		hkp.PksIndexTemplate.ExecuteTemplate(w, "index-bottom", nil)
	}
	return err
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

func AlgorithmCode(algorithm int) string {
	switch packet.PublicKeyAlgorithm(algorithm) {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		return "R"
	case packet.PubKeyAlgoElGamal:
		return "g"
	case packet.PubKeyAlgoDSA:
		return "D"
	}
	return fmt.Sprintf("[%d]", algorithm)
}

func qrEncodeToDataUri(s string) string {
	var err error
	grid, err := qrencode.Encode(s, qrencode.ECLevelQ)
	if err != nil {
		return ""
	}
	img := grid.Image(3)
	pngbuf := bytes.NewBuffer([]byte{})
	err = png.Encode(pngbuf, img)
	if err != nil {
		return ""
	}
	return encodeToDataUri(pngbuf.Bytes())
}

func encodeToDataUri(data []byte) string {
	return url.QueryEscape(base64.StdEncoding.EncodeToString(data))
}

func (i *IndexResponse) WriteIndex(w io.Writer, key *Pubkey) error {
	if hkp.PksIndexTemplate == nil {
		return ErrTemplatePathNotFound
	}
	key.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			hkp.PksIndexTemplate.ExecuteTemplate(w, "pub-index-row", struct {
				KeyLength    int
				AlgoCode     string
				Fingerprint  string
				FpQrCode     string
				ShortId      string
				CreationTime string
			}{
				r.BitLen,
				AlgorithmCode(r.Algorithm),
				r.Fingerprint(),
				qrEncodeToDataUri(r.Fingerprint()),
				strings.ToUpper(r.Fingerprint()[32:40]),
				r.Creation.Format("2006-01-02")})
		case *UserId:
			hkp.PksIndexTemplate.ExecuteTemplate(w, "uid-index-row", struct {
				Fingerprint string
				Id          string
			}{
				key.Fingerprint(),
				r.Keywords})
		case *Signature:
			if i.Verbose {
				hkp.PksIndexTemplate.ExecuteTemplate(w, "sig-vindex-row", struct {
					LongId  string
					ShortId string
					SigTime string
					Uid     string
				}{
					r.IssuerKeyId(),
					r.IssuerKeyId()[8:16],
					r.Creation.Format("2006-01-02"), ""}) // TODO: use issuer primary UID
			}
		case *UserAttribute:
			for _, imageData := range r.GetJpegData() {
				hkp.PksIndexTemplate.ExecuteTemplate(w, "uattr-image-row", struct {
					ImageData string
				}{
					encodeToDataUri(imageData.Bytes())})
			}
		}
		return nil
	})
	return nil
}

func (i *IndexResponse) WriteMachineReadable(w io.Writer, key *Pubkey) error {
	key.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			fmt.Fprintf(w, "pub:%s:%d:%d:%d:%s:\n",
				strings.ToUpper(r.Fingerprint()),
				r.Algorithm, r.BitLen,
				r.Creation.Unix(),
				r.Expiration.Unix())
		case *UserId:
			fmt.Fprintf(w, "uid:%s:%s:%s:\n",
				r.Keywords, r.Creation.Unix(), r.Expiration.Unix())
		case *Signature:
			if i.Verbose {
				fmt.Fprintf(w, "sig:%s:%s:%s",
					r.Creation.Unix(), r.Expiration.Unix(), r.IssuerKeyId())
			}
		case *UserAttribute:
			fmt.Fprintf(w, "uat::::\n")
		case *Subkey:
			fmt.Fprintf(w, "sub:%s:%d:%d:%d:%s:\n",
				strings.ToUpper(r.Fingerprint()),
				r.Algorithm, r.BitLen,
				r.Creation.Unix(),
				r.Expiration.Unix())
		}
		return nil
	})
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
