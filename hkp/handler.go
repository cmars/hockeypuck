package hkp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/openpgp/armor"
	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/conflux.v2/recon"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/statsd.v1"

	"github.com/hockeypuck/hockeypuck/openpgp"
	"github.com/hockeypuck/hockeypuck/util"
)

type Handler struct {
	storage Storage
}

func httpError(w http.ResponseWriter, statusCode int, err error) {
	log.Errorf("HTTP %d: %v", statusCode, err)
	statsd.Increment(fmt.Sprintf("hkp.status.%d", statusCode), 1, 1)
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func (h *Handler) Register(r *httprouter.Router) {
	r.GET("/pks/lookup", h.Lookup)
	r.POST("/pks/add", h.Add)
	r.POST("/pks/hashquery", h.HashQuery)
}

func (h *Handler) Lookup(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	l, err := ParseLookup(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	switch l.Op {
	case OperationGet, OperationHGet:
		h.get(w, l)
	case OperationIndex:
		h.index(w, l)
	case OperationVIndex:
		h.vindex(w, l)
	default:
		httpError(w, http.StatusNotFound, errgo.Newf("operation not found: %v", l.Op))
	}
}

func (h *Handler) HashQuery(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	hq, err := ParseHashQuery(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	}
	var result []*openpgp.Pubkey
	for _, digest := range hq.Digests {
		rfps, err := h.storage.MatchMD5([]string{digest})
		if err != nil {
			log.Errorf("error resolving hashquery digest %q", digest)
			continue
		}
		keys, err := h.storage.FetchKeys(rfps)
		if err != nil {
			log.Errorf("error fetching hashquery key %q", digest)
			continue
		}
		result = append(result, keys...)
	}

	w.Header().Set("Content-Type", "pgp/keys")

	// Write the number of keys
	err = recon.WriteInt(w, len(result))
	for _, key := range result {
		// Write each key in binary packet format, prefixed with length
		err = writeHashqueryKey(w, key)
		if err != nil {
			log.Errorf("error writing hashquery key %q: %v", key.RFingerprint, err)
			return
		}
	}

	// SKS expects hashquery response to terminate with a CRLF
	_, err = w.Write([]byte{0x0d, 0x0a})
	if err != nil {
		log.Errorf("error writing hashquery terminator: %v", err)
	}
}

func writeHashqueryKey(w http.ResponseWriter, key *openpgp.Pubkey) error {
	var buf bytes.Buffer
	err := openpgp.WritePackets(&buf, key)
	if err != nil {
		return errgo.Mask(err)
	}
	err = recon.WriteInt(w, buf.Len())
	if err != nil {
		return errgo.Mask(err)
	}
	_, err = w.Write(buf.Bytes())
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

func (h *Handler) resolve(l *Lookup) ([]string, error) {
	if l.Op == OperationHGet {
		return h.storage.MatchMD5([]string{l.Search})
	}
	if strings.HasPrefix(l.Search, "0x") {
		keyID := util.Reverse(strings.ToLower(l.Search[2:]))
		return h.storage.Resolve([]string{keyID})
	}
	return h.storage.MatchKeyword([]string{l.Search})
}

func (h *Handler) keys(l *Lookup) ([]*openpgp.Pubkey, error) {
	rfps, err := h.resolve(l)
	if err != nil {
		return nil, err
	}
	return h.storage.FetchKeys(rfps)
}

func (h *Handler) get(w http.ResponseWriter, l *Lookup) {
	keys, err := h.keys(l)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
	}

	w.Header().Set("Content-Type", "text/plain")
	err = openpgp.WriteArmoredPackets(w, keys)
	if err != nil {
		log.Errorf("get %q: error writing armored keys: %v", l.Search, err)
	}
}

func (h *Handler) index(w http.ResponseWriter, l *Lookup) {
	keys, err := h.keys(l)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
	}

	// TODO: support other format types besides JSON
	h.indexJSON(w, keys)
}

func (h *Handler) vindex(w http.ResponseWriter, l *Lookup) {
	keys, err := h.keys(l)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
	}

	// TODO: support other format types besides JSON
	h.indexJSON(w, keys)
}

func (h *Handler) indexJSON(w http.ResponseWriter, keys []*openpgp.Pubkey) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err := enc.Encode(&keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
	}
}

func (h *Handler) Add(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	add, err := ParseAdd(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(add.Keytext))
	if err != nil {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	}

	for readKey := range openpgp.ReadKeys(armorBlock.Body) {
		if readKey.Error != nil {
			httpError(w, http.StatusBadRequest, errgo.Mask(err))
			return
		}
		err := h.upsertKey(readKey.Pubkey)
		if err != nil {
			httpError(w, http.StatusInternalServerError, errgo.Mask(err))
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	// TODO: respond with JSON stats on updated key information
}

func (h *Handler) upsertKey(pubkey *openpgp.Pubkey) error {
	panic("TODO")
}
