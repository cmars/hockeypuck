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
	"bitbucket.org/cmars/go.crypto/openpgp/packet"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/qpliu/qrencode-go/qrencode"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type MessageResponse struct {
	Content string
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
	Fingerprints []string
	Err          error
}

func (r *AddResponse) Error() error {
	return r.Err
}

func (r *AddResponse) WriteTo(w http.ResponseWriter) (err error) {
	err = AddResultTemplate.ExecuteTemplate(w, "top", r)
	if err != nil {
		return
	}
	err = AddResultTemplate.ExecuteTemplate(w, "page_content", r)
	if err != nil {
		return
	}
	err = AddResultTemplate.ExecuteTemplate(w, "bottom", r)
	return
}

type IndexResponse struct {
	Lookup *Lookup
	Keys   []*PubKey
	Err    error
}

func (r *IndexResponse) Error() error {
	return r.Err
}

func (r *IndexResponse) WriteTo(w http.ResponseWriter) error {
	err := r.Err
	var writeFn func(io.Writer, *PubKey) error = nil
	switch {
	case r.Lookup.Option&MachineReadable != 0:
		writeFn = WriteMachineReadable
	case r.Lookup.Op == Vindex:
		writeFn = WriteVindex
	case r.Lookup.Op == Index:
		writeFn = WriteIndex
	}
	if r.Lookup.Option&MachineReadable != 0 {
		writeFn = WriteMachineReadable
		w.Header().Add("Content-Type", "text/plain")
		fmt.Fprintf(w, "info:1:%d\n", len(r.Keys))
	} else {
		w.Header().Add("Content-Type", "text/html")
		err = PksIndexTemplate.ExecuteTemplate(w, "index-top", r.Lookup.Search)
	}
	if writeFn == nil {
		err = UnsupportedOperation
	}
	if len(r.Keys) == 0 {
		err = KeyNotFound
	}
	if err == nil {
		for _, key := range r.Keys {
			err = writeFn(w, key)
		}
	} else {
		w.Write([]byte(err.Error()))
	}
	if r.Lookup.Option&MachineReadable == 0 {
		PksIndexTemplate.ExecuteTemplate(w, "index-bottom", nil)
	}
	return err
}

type StatusResponse struct {
	Status *ServerStatus
	Err    error
}

func (r *StatusResponse) Error() error {
	return r.Err
}

func (r *StatusResponse) WriteTo(w http.ResponseWriter) (err error) {
	err = r.Err
	if err != nil {
		return
	}
	err = StatusTemplate.ExecuteTemplate(w, "layout", r.Status)
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

func WriteIndex(w io.Writer, key *PubKey) error {
	pktObjChan := make(chan PacketObject)
	go func() {
		key.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	for pktObj := range pktObjChan {
		switch pktObj.(type) {
		case *PubKey:
			pubKey := pktObj.(*PubKey)
			pkt, err := pubKey.Parse()
			if err != nil {
				return err
			}
			pk := pkt.(*packet.PublicKey)
			PksIndexTemplate.ExecuteTemplate(w, "pub-index-row", struct {
				KeyLength    uint16
				AlgoCode     string
				Fingerprint  string
				FpQrCode     string
				ShortId      string
				CreationTime string
			}{
				key.KeyLength,
				AlgorithmCode(key.Algorithm),
				key.Fingerprint,
				qrEncodeToDataUri(key.Fingerprint),
				strings.ToUpper(key.Fingerprint[32:40]),
				pk.CreationTime.Format("2006-01-02")})
		case *UserId:
			uid := pktObj.(*UserId)
			PksIndexTemplate.ExecuteTemplate(w, "uid-index-row", struct {
				Fingerprint string
				Id          string
			}{
				key.Fingerprint,
				uid.Id})
		case *UserAttribute:
			uattr := pktObj.(*UserAttribute)
			for _, imageData := range uattr.GetJpegData() {
				PksIndexTemplate.ExecuteTemplate(w, "uattr-image-row", struct {
					ImageData string
				}{
					encodeToDataUri(imageData.Bytes())})
			}
		}
	}
	return nil
}

func WriteVindex(w io.Writer, key *PubKey) error {
	pktObjChan := make(chan PacketObject)
	go func() {
		key.Traverse(pktObjChan)
		close(pktObjChan)
	}()
	for pktObj := range pktObjChan {
		switch pktObj.(type) {
		case *PubKey:
			pubKey := pktObj.(*PubKey)
			pkt, err := pubKey.Parse()
			if err != nil {
				return err
			}
			pk := pkt.(*packet.PublicKey)
			PksIndexTemplate.ExecuteTemplate(w, "pub-index-row", struct {
				KeyLength    uint16
				AlgoCode     string
				Fingerprint  string
				FpQrCode     string
				ShortId      string
				CreationTime string
			}{
				key.KeyLength,
				AlgorithmCode(key.Algorithm),
				key.Fingerprint,
				qrEncodeToDataUri(key.Fingerprint),
				strings.ToUpper(key.Fingerprint[32:40]),
				pk.CreationTime.Format("2006-01-02")})
		case *UserId:
			uid := pktObj.(*UserId)
			PksIndexTemplate.ExecuteTemplate(w, "uid-index-row", struct {
				Fingerprint string
				Id          string
			}{
				key.Fingerprint,
				uid.Id})
		case *Signature:
			sig := pktObj.(*Signature)
			longId := strings.ToUpper(hex.EncodeToString(sig.IssuerKeyId))
			pkt, err := sig.Parse()
			if err != nil {
				return err
			}
			sigv4, isa := pkt.(*packet.Signature)
			var sigTime string
			if isa {
				sigTime = sigv4.CreationTime.Format("2006-01-02")
			}
			PksIndexTemplate.ExecuteTemplate(w, "sig-vindex-row", struct {
				LongId  string
				ShortId string
				SigTime string
			}{
				longId,
				longId[8:16],
				sigTime})
		case *UserAttribute:
			uattr := pktObj.(*UserAttribute)
			for _, imageData := range uattr.GetJpegData() {
				PksIndexTemplate.ExecuteTemplate(w, "uattr-image-row", struct {
					ImageData string
				}{
					encodeToDataUri(imageData.Bytes())})
			}
		}
	}
	return nil
}

func WriteMachineReadable(w io.Writer, key *PubKey) error {
	pkt, err := key.Parse()
	if err != nil {
		return err
	}
	pk := pkt.(*packet.PublicKey)
	var keyExpiration string
	if keySelfSig := key.SelfSignature(); keySelfSig != nil && keySelfSig.KeyExpirationTime < NeverExpires {
		keyExpiration = fmt.Sprintf("%d", keySelfSig.KeyExpirationTime)
	}
	fmt.Fprintf(w, "pub:%s:%d:%d:%d:%s:\n",
		key.Fingerprint,
		key.Algorithm, key.KeyLength,
		pk.CreationTime.Unix(),
		keyExpiration)
	for _, uid := range key.Identities {
		pkt, err = uid.Parse()
		if err != nil {
			return err
		}
		var sigCreation string
		var sigExpiration string
		if uidSelfSig := uid.SelfSignature(); uidSelfSig != nil {
			sigCreation = fmt.Sprintf("%d", uidSelfSig.CreationTime)
			if uidSelfSig.SigExpirationTime < NeverExpires {
				sigExpiration = fmt.Sprintf("%d", uidSelfSig.SigExpirationTime)
			}
		}
		fmt.Fprintf(w, "uid:%s:%s:%s:\n", uid.Id, sigCreation, sigExpiration)
	}
	return nil
}

type NotImplementedResponse struct {
}

func (e *NotImplementedResponse) Error() error {
	return errors.New("Not implemented")
}

func (e *NotImplementedResponse) WriteTo(_ http.ResponseWriter) error {
	return e.Error()
}
