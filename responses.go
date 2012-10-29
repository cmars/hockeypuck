package hockeypuck

import (
	"encoding/hex"
	"errors"
	"fmt"
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
	if r.Lookup.Option & MachineReadable == 0 {
		PksIndexTemplate.ExecuteTemplate(w, "index-bottom", nil)
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
			PksIndexTemplate.ExecuteTemplate(w, "pub-index-row", struct {
				KeyLength uint16
				AlgoCode string
				Fingerprint string
				ShortId string
				CreationTime string
			}{
				key.KeyLength,
				AlgorithmCode(key.Algorithm),
				key.Fingerprint,
				strings.ToUpper(key.Fingerprint[32:40]),
				pk.CreationTime.Format("2006-01-02")})
		case *UserId:
			uid := pktObj.(*UserId)
			PksIndexTemplate.ExecuteTemplate(w, "uid-index-row", struct {
				Fingerprint string
				Id string
			}{
				key.Fingerprint,
				uid.Id})
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
				KeyLength uint16
				AlgoCode string
				Fingerprint string
				ShortId string
				CreationTime string
			}{
				key.KeyLength,
				AlgorithmCode(key.Algorithm),
				key.Fingerprint,
				strings.ToUpper(key.Fingerprint[32:40]),
				pk.CreationTime.Format("2006-01-02")})
		case *UserId:
			uid := pktObj.(*UserId)
			PksIndexTemplate.ExecuteTemplate(w, "uid-index-row", struct {
				Fingerprint string
				Id string
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
				LongId string
				ShortId string
				SigTime string
			}{
				longId,
				longId[8:16],
				sigTime})
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
