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
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"gopkg.in/errgo.v1"
	log "gopkg.in/hockeypuck/logrus.v0"

	"github.com/hockeypuck/hockeypuck"
	"github.com/hockeypuck/hockeypuck/hkp"
	"github.com/hockeypuck/hockeypuck/util"
)

const LOOKUP_RESULT_LIMIT = 100

type Worker struct {
	*Loader
	settings   *hockeypuck.Settings
	Service    *hkp.Service
	Peer       *SksPeer
	keyChanges KeyChangeChan
}

func currentUsername() string {
	var username string
	if me, err := user.Current(); err != nil {
		username = os.Getenv("USER")
	} else {
		username = me.Name
	}
	return username
}

func NewWorker(service *hkp.Service, peer *SksPeer) (w *Worker, err error) {
	w = &Worker{Loader: &Loader{}, Service: service, Peer: peer, settings: peer.settings}
	if w.db, err = NewDB(peer.settings); err != nil {
		return
	}
	err = w.db.CreateSchema()
	return
}

func (w *Worker) Run() {
	go w.monitorStats()
	for {
		select {
		case req, ok := <-w.Service.Requests:
			if !ok {
				return
			}
			switch r := req.(type) {
			case *hkp.Lookup:
				w.Lookup(r)
			case *hkp.Add:
				w.Add(r)
			case *hkp.HashQuery:
				w.HashQuery(r)
			default:
				log.Warnf("unsupported HKP service request: %+v", req)
			}
		case r, ok := <-w.Peer.RecoverKey:
			if !ok {
				return
			}
			resp := w.recoverKey(&r)
			log.Debug(resp)
			r.response <- resp
		}
	}
}

func (w *Worker) Lookup(l *hkp.Lookup) {
	// Dispatch the lookup operation to the correct query
	if l.Op == hkp.Stats {
		w.Stats(l)
		return
	} else if l.Op == hkp.UnknownOperation {
		l.Response() <- &ErrorResponse{hkp.ErrorUnknownOperation("")}
		return
	}
	var keys []*Pubkey
	var limit int = LOOKUP_RESULT_LIMIT
	var err error
	if l.Op == hkp.HashGet {
		keys, err = w.LookupHash(l.Search)
	} else {
		keys, err = w.LookupKeys(l.Search, limit)
	}
	if err != nil {
		l.Response() <- &ErrorResponse{err}
		return
	}
	// Formulate a response
	var resp hkp.Response
	switch l.Op {
	case hkp.Get:
		resp = &KeyringResponse{keys}
	case hkp.HashGet:
		resp = &KeyringResponse{keys}
	case hkp.Index:
		resp = &IndexResponse{Lookup: l, Keys: keys}
	case hkp.Vindex:
		resp = &IndexResponse{Lookup: l, Keys: keys, Verbose: true}
	default:
		resp = &ErrorResponse{hockeypuck.ErrUnsupportedOperation}
		return
	}
	l.Response() <- resp
}

func (w *Worker) HashQuery(hq *hkp.HashQuery) {
	var uuids []string
	for _, digest := range hq.Digests {
		// Look up key in storage
		uuid, err := w.lookupMd5Uuid(digest)
		if hockeypuck.IsNotFound(err) {
			// Must have gotten into our prefix tree if peer thinks we have it.
			// Remove the digest to self-correct.
			err = w.removeMissingDigest(digest)
			if err != nil {
				log.Errorf("remove missing key md5=%q from recon: %v", digest, errgo.Details(err))
			}
		} else if err != nil {
			log.Errorf("hashquery: failed to look up key md5=%q: %v", digest, errgo.Details(err))
		} else {
			uuids = append(uuids, uuid)
		}
	}
	keys := w.fetchKeys(uuids)
	hq.Response() <- &HashQueryResponse{keys.GoodKeys()}
}

func (w *Worker) removeMissingDigest(digest string) error {
	z, err := DigestZp(digest)
	if err != nil {
		return errgo.Mask(err)
	}
	w.Peer.RemoveWith(func(err error) {
		if err != nil {
			log.Errorf("failed to remove %q: %v", z, errgo.Details(err))
		} else {
			log.Debugf("removed %q from prefix tree", z.String())
		}
	}, z)
	return nil
}

func (w *Worker) LookupKeys(search string, limit int) ([]*Pubkey, error) {
	uuids, err := w.lookupPubkeyUuids(search, limit)
	return w.fetchKeys(uuids).GoodKeys(), errgo.Mask(err)
}

func (w *Worker) LookupHash(digest string) ([]*Pubkey, error) {
	uuid, err := w.lookupMd5Uuid(digest)
	return w.fetchKeys([]string{uuid}).GoodKeys(), errgo.Mask(err)
}

func (w *Worker) lookupPubkeyUuids(search string, limit int) ([]string, error) {
	if strings.HasPrefix(search, "0x") {
		return w.lookupKeyidUuids(search[2:])
	}
	return w.lookupKeywordUuids(search, limit)
}

func (w *Worker) lookupMd5Uuid(hash string) (string, error) {
	fail := ""
	rows, err := w.db.Queryx(`SELECT uuid FROM openpgp_pubkey WHERE md5 = $1`,
		strings.ToLower(hash))
	if err == sql.ErrNoRows {
		return fail, errgo.Mask(hockeypuck.ErrKeyNotFound, hockeypuck.IsNotFound)
	} else if err != nil {
		return fail, errgo.Mask(err)
	}
	uuids, err := flattenUuidRows(rows)
	if err != nil {
		return fail, errgo.Mask(err)
	}
	if len(uuids) < 1 {
		return fail, errgo.Mask(hockeypuck.ErrKeyNotFound, hockeypuck.IsNotFound)
	}
	uuid := uuids[0]
	if len(uuids) > 1 {
		return fail, errgo.Mask(hockeypuck.ErrKeyIdCollision)
	}
	return uuid, nil
}

func (w *Worker) lookupKeyidUuids(keyId string) ([]string, error) {
	keyId = strings.ToLower(keyId)
	raw, err := hex.DecodeString(keyId)
	if err != nil {
		return nil, errgo.Mask(hockeypuck.ErrInvalidKeyId)
	}
	rKeyId := util.Reverse(keyId)
	var compareOp string
	switch len(raw) {
	case 4:
		compareOp = "LIKE $1 || '________________________________'"
	case 8:
		compareOp = "LIKE $1 || '________________________'"
	case 16:
		return []string{rKeyId}, nil
	case 20:
		return []string{rKeyId}, nil
	default:
		return nil, errgo.Mask(hockeypuck.ErrInvalidKeyId)
	}
	rows, err := w.db.Queryx(fmt.Sprintf(`
SELECT uuid FROM openpgp_pubkey WHERE uuid %s
UNION
SELECT pubkey_uuid FROM openpgp_subkey WHERE uuid %s`, compareOp, compareOp), rKeyId)
	if err == sql.ErrNoRows {
		return nil, errgo.Mask(hockeypuck.ErrKeyNotFound, hockeypuck.IsNotFound)
	} else if err != nil {
		return nil, errgo.Mask(err)
	}
	return flattenUuidRows(rows)
}

func flattenUuidRows(rows *sqlx.Rows) ([]string, error) {
	var uuids []string
	for rows.Next() {
		var uuid string
		err := rows.Scan(&uuid)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		uuids = append(uuids, uuid)
	}
	return uuids, nil
}

func (w *Worker) lookupKeywordUuids(search string, limit int) ([]string, error) {
	search = strings.Join(strings.Split(search, " "), "+")
	log.Debugf("keyword: %q", search)
	log.Debugf("limit: %d", limit)
	rows, err := w.db.Queryx(`
SELECT DISTINCT pubkey_uuid FROM openpgp_uid
WHERE keywords_fulltext @@ to_tsquery($1) LIMIT $2`, search, limit)
	if err == sql.ErrNoRows {
		return nil, errgo.Mask(hockeypuck.ErrKeyNotFound, hockeypuck.IsNotFound)
	} else if err != nil {
		return nil, errgo.Mask(err)
	}
	return flattenUuidRows(rows)
}

var ErrInternalKeyInvalid error = fmt.Errorf("Internal integrity error matching key")

func (w *Worker) LookupKey(keyid string) (*Pubkey, error) {
	uuids, err := w.lookupKeyidUuids(keyid)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if len(uuids) < 1 {
		return nil, errgo.Mask(hockeypuck.ErrKeyNotFound, hockeypuck.IsNotFound)
	}
	if len(uuids) > 1 {
		return nil, hockeypuck.ErrKeyIdCollision
	}
	return w.FetchKey(uuids[0])
}

func (w *Worker) fetchKeys(uuids []string) ReadKeyResults {
	var results ReadKeyResults
	for _, uuid := range uuids {
		key, err := w.FetchKey(uuid)
		results = append(results, &ReadKeyResult{Pubkey: key, Error: err})
		if err != nil {
			log.Errorf("failed to fetch key: %v", err)
		}
	}
	return results
}

func (w *Worker) FetchKey(uuid string) (*Pubkey, error) {
	pubkey := new(Pubkey)
	err := w.db.Get(pubkey, `SELECT * FROM openpgp_pubkey WHERE uuid = $1`, uuid)
	if err == sql.ErrNoRows {
		return nil, errgo.Mask(hockeypuck.ErrKeyNotFound, hockeypuck.IsNotFound)
	} else if err != nil {
		return nil, errgo.Mask(err)
	}
	if err = pubkey.Read(); err != nil {
		return nil, errgo.Mask(err)
	}
	// Retrieve all signatures made directly on the primary public key
	sigs := []Signature{}
	err = w.db.Select(&sigs, `
SELECT * FROM openpgp_sig WHERE pubkey_uuid = $1
	AND subkey_uuid IS NULL AND uid_uuid IS NULL AND uat_uuid IS NULL AND sig_uuid IS NULL`,
		uuid)
	if err != nil && err != sql.ErrNoRows {
		return nil, errgo.Mask(err)
	}
	pubkey.signatures = toSigPtrSlice(sigs)
	for _, sig := range pubkey.signatures {
		if err = sig.Read(); err != nil {
			return nil, errgo.Mask(err)
		}
	}
	// Retrieve all uid records
	uids := []UserId{}
	err = w.db.Select(&uids, `
SELECT uuid, creation, expiration, state, packet, pubkey_uuid, revsig_uuid, keywords
FROM openpgp_uid WHERE pubkey_uuid = $1`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return nil, errgo.Mask(err)
	}
	pubkey.userIds = toUidPtrSlice(uids)
	for _, uid := range pubkey.userIds {
		if err = uid.Read(); err != nil {
			return nil, errgo.Mask(err)
		}
		sigs = []Signature{}
		err = w.db.Select(&sigs, `
SELECT * FROM openpgp_sig WHERE pubkey_uuid = $1 AND uid_uuid = $2
	AND subkey_uuid IS NULL AND uat_uuid IS NULL AND sig_uuid IS NULL`, uuid, uid.ScopedDigest)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		uid.signatures = toSigPtrSlice(sigs)
		for _, sig := range uid.signatures {
			if err = sig.Read(); err != nil {
				return nil, errgo.Mask(err)
			}
		}
	}
	// Retrieve all user attribute records
	uats := []UserAttribute{}
	err = w.db.Select(&uats,
		`SELECT * FROM openpgp_uat WHERE pubkey_uuid = $1`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return nil, errgo.Mask(err)
	}
	pubkey.userAttributes = toUatPtrSlice(uats)
	for _, uat := range pubkey.userAttributes {
		if err = uat.Read(); err != nil {
			return nil, errgo.Mask(err)
		}
		sigs = []Signature{}
		err = w.db.Select(&sigs, `
SELECT * FROM openpgp_sig WHERE pubkey_uuid = $1 AND uat_uuid = $2
	AND subkey_uuid IS NULL AND uid_uuid IS NULL AND sig_uuid IS NULL`, uuid, uat.ScopedDigest)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		uat.signatures = toSigPtrSlice(sigs)
		for _, sig := range uat.signatures {
			if err = sig.Read(); err != nil {
				return nil, errgo.Mask(err)
			}
		}
	}
	// Retrieve all subkey records
	subkeys := []Subkey{}
	err = w.db.Select(&subkeys,
		`SELECT * FROM openpgp_subkey WHERE pubkey_uuid = $1`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return nil, errgo.Mask(err)
	}
	pubkey.subkeys = toSubkeyPtrSlice(subkeys)
	for _, subkey := range pubkey.subkeys {
		if err = subkey.Read(); err != nil {
			return nil, errgo.Mask(err)
		}
		sigs = []Signature{}
		err = w.db.Select(&sigs, `
SELECT * FROM openpgp_sig sig WHERE pubkey_uuid = $1 AND subkey_uuid = $2
	AND uid_uuid IS NULL AND uat_uuid IS NULL AND sig_uuid IS NULL`, uuid, subkey.RFingerprint)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		subkey.signatures = toSigPtrSlice(sigs)
		for _, sig := range subkey.signatures {
			if err = sig.Read(); err != nil {
				return nil, errgo.Mask(err)
			}
		}
	}
	Resolve(pubkey)

	digest := SksDigest(pubkey, md5.New())
	if digest != pubkey.Md5 {
		log.Warnf("digest mismatch for key %q: indexed=%q material=%q",
			pubkey.Fingerprint(), pubkey.Md5, digest)
	}

	return pubkey, nil
}

func toSigPtrSlice(recs []Signature) []*Signature {
	var result []*Signature
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return result
}

func toUidPtrSlice(recs []UserId) []*UserId {
	var result []*UserId
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return result
}

func toUatPtrSlice(recs []UserAttribute) []*UserAttribute {
	var result []*UserAttribute
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return result
}

func toSubkeyPtrSlice(recs []Subkey) []*Subkey {
	var result []*Subkey
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return result
}
