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
	"code.google.com/p/go.crypto/openpgp/armor"
	"crypto/rand"
	"database/sql"
	"encoding/ascii85"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"io"
	"launchpad.net/hockeypuck/hkp"
	"strings"
)

type KeyChangeChan chan *KeyChange

func (w *Worker) Add(a *hkp.Add) {
	// Parse armored keytext
	var keys []*Pubkey
	var changes []*KeyChange
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(a.Keytext))
	if err != nil {
		return err
	}
	keys, err := ReadKeys(armorBlock.Body)
	if err != nil {
		a.Response() <- &ErrorResponse{err}
		return
	}
	// Upsert keys
	for _, key := range keys {
		change := w.UpsertKey(key)
		changes = append(changes, change)
	}
	a.Response() <- &AddResponse{Changes: changes}
}

type KeyChange struct {
	Fingerprint    string
	Type           KeyChangeType
	CurrentMd5     string
	PreviousMd5    string
	CurrentSha256  string
	PreviousSha256 string
	Error          error
}

func (kc *KeyChange) String() string {
	w := bytes.NewBuffer(nil)
	var msg string
	switch kc.Type {
	case KeyChangeInvalid:
		msg = fmt.Sprintf("Invalid key change for [%s] could not be processed",
			kc.Fingerprint)
	case KeyAdded:
		msg = fmt.Sprintf("Add key %s, [%s..]", kc.Fingerprint, kc.CurrentSha256[:8])
	case KeyModified:
		msg = fmt.Sprintf("Modify key %s, [%s.. -> %s..]", kc.Fingerprint,
			kc.PreviousSha256[:8], kc.CurrentSha256[:8])
	case KeyNotChange:
		msg = fmt.Sprintf("No change in key %s", kc.Fingerprint)
	}
	w.Write([]byte(msg))
	if kc.Error != nil {
		w.Write([]byte(": Error: %v", kc.Error))
	}
	return w.String()
}

type KeyChangeType int

const (
	KeyChangeInvalid KeyChangeType = iota
	KeyNotChanged    KeyChangeType = iota
	KeyAdded         KeyChangeType = iota
	KeyModified      KeyChangeType = iota
)

func (change *KeyChange) Type() KeyChangeType {
	if result.CurrentSha256 == "" {
		return KeyChangeInvalid
	} else if result.PreviousSha256 == "" {
		return KeyAdded
	} else if result.PreviousSha256 == result.CurrentSha256 {
		return KeyNotChanged
	}
	return KeyModified
}

func (w *Worker) UpsertKey(key *Pubkey) (change *KeyChange) {
	change = &KeyChange{Fingerprint: key.Fingerprint(), Type: KeyChangeInvalid}
	lastKey, err := w.LookupKey(key.Fingerprint())
	if err == KeyNotFound {
		change.PreviousMd5 = ""
		change.PreviousSha256 = ""
		change.CurrentMd5 = key.Md5
		change.CurrentSha256 = key.Sha256
		change.Type = KeyAdded
	} else if err != nil {
		change.Error = err
		return
	} else {
		change.PreviousMd5 = lastKey.Md5
		change.PreviousSha256 = lastKey.Sha256
		MergeKey(lastKey, key)
		change.CurrentMd5 = lastKey.Md5
		change.CurrentSha256 = lastKey.Sha256
		if change.PreviousSha256 == change.CurrentSha256 {
			change.Type = KeyNotChanged
		} else {
			change.Type = KeyModified
		}
	}
	if change.CurrentSha256 == "" {
		change.Type = KeyChangeInvalid
	}
	switch result.Action() {
	case KeyAdded:
		lastKey.SetMtime(time.Now().UnixNano())
		change.Error = w.UpdateKey(lastKey)
	case KeyChanged:
		key.Ctime = time.Now().UnixNano()
		key.Mtime = key.Ctime
		change.Error = w.InsertKey(key)
	}
	log.Println(change)
	return
}
