package hockeypuck

import (
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"bitbucket.org/cmars/go.crypto/openpgp/packet"
)

type MessageResponse struct {
	Content string
	Err error
}

func (r *MessageResponse) Error() error {
	return r.Err
}

func (r *MessageResponse) WriteTo(w http.ResponseWriter) error {
	w.Write([]byte(r.Content))
	return r.Err
}

type IndexResponse struct {
	Lookup *Lookup
	Keys []*PubKey
	Err error
}

func (r *IndexResponse) Error() error {
	return r.Err
}

func (r *IndexResponse) WriteTo(w http.ResponseWriter) error {
	err := r.Err
	var writeFn func(io.Writer, *PubKey) error = nil
	switch {
	case r.Lookup.Option & MachineReadable != 0:
		writeFn = WriteMachineReadable
	case r.Lookup.Op == Vindex:
		writeFn = WriteVindex
	case r.Lookup.Op == Index:
		writeFn = WriteIndex
	}
	if r.Lookup.Option & MachineReadable != 0 {
		writeFn = WriteMachineReadable
		w.Header().Add("Content-Type", "text/plain")
		fmt.Fprintf(w, "info:1:%d\n", len(r.Keys))
	} else {
		w.Header().Add("Content-Type", "text/html")
		w.Write([]byte(`<html><body><pre>`))
		w.Write([]byte(`<table>
<tr><th>Type</th><th>bits/keyID</th><th>Created</th><th></th></tr>`))
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
	if r.Lookup.Option & MachineReadable == 0 {
		if r.Lookup.Op == Index {
			w.Write([]byte(`</table>`))
		}
		w.Write([]byte(`</pre></body></html>`))
	}
	return err
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
			fmt.Fprintf(w, `<tr>
<td>pub</td>
<td>%d%s/<a href="/pks/lookup?op=get&search=0x%s">%s</a></td>
<td>%v</td>
<td></td></tr>`,
				key.KeyLength, AlgorithmCode(key.Algorithm), key.Fingerprint,
				strings.ToUpper(key.Fingerprint[32:40]),
				pk.CreationTime.Format("2006-01-02"))
		case *UserId:
			uid := pktObj.(*UserId)
			fmt.Fprintf(w, `<tr><td>uid</td><td colspan='2'></td>
<td><a href="/pks/lookup?op=vindex&search=0x%s">%s</a></td></tr>`,
				key.Fingerprint, html.EscapeString(uid.Id))
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
			fmt.Fprintf(w, `<tr>
<td>pub</td>
<td>%d%s/<a href="/pks/lookup?op=get&search=0x%s">%s</a></td>
<td>%v</td>
<td></td></tr>`,
				key.KeyLength, AlgorithmCode(key.Algorithm), key.Fingerprint,
				strings.ToUpper(key.Fingerprint[32:40]),
				pk.CreationTime.Format("2006-01-02"))
		case *UserId:
			uid := pktObj.(*UserId)
			fmt.Fprintf(w, `<tr><td>uid</td><td colspan='2'></td>
<td><a href="/pks/lookup?op=vindex&search=0x%s">%s</a></td></tr>`,
				key.Fingerprint, html.EscapeString(uid.Id))
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
			fmt.Fprintf(w, `<tr><td>sig</td><td>%s</td><td>%s</td>
<td><a href="/pks/lookup?op=vindex&search=0x%s">%s</a></td></tr>`,
				longId[8:16], sigTime, longId, longId)
/*
		case *UserAttribute:
			uattr := pktObj.(*UserAttribute)
			pkt, err := uattr.Parse()
			if err != nil {
				continue
			}
			if opkt, isa := pkt.(*packet.OpaquePacket); isa {
				fmt.Fprintf(w, `<tr><td>uattr</td><td colspan=2></td>
<td><img src="data:image/jpeg;base64,%s"></img></td></tr>`,
					base64.URLEncoding.EncodeToString(opkt.Contents[22:]))
			}
*/
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
	if keySelfSig := key.SelfSignature();
			keySelfSig != nil && keySelfSig.KeyExpirationTime < NeverExpires {
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
