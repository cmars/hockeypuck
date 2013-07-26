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
	"fmt"
	"launchpad.net/hockeypuck"
	"launchpad.net/hockeypuck/hkp"
	"log"
	"time"
)

type KeyChangeChan chan *KeyChange

func (w *Worker) Add(a *hkp.Add) {
	// Parse armored keytext
	var changes []*KeyChange
	var errors []*ReadKeyResult
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(a.Keytext))
	if err != nil {
		a.Response() <- &ErrorResponse{err}
		return
	}
	var readErrors []*ReadKeyResult
	for readKey := range ReadKeys(armorBlock.Body) {
		if readKey.Error != nil {
			readErrors = append(readErrors, readKey)
		} else {
			change := w.UpsertKey(readKey.Pubkey)
			changes = append(changes, change)
		}
	}
	a.Response() <- &AddResponse{Changes: changes, Errors: readErrors}
}

type KeyChangeType int

const (
	KeyChangeInvalid KeyChangeType = iota
	KeyNotChanged    KeyChangeType = iota
	KeyAdded         KeyChangeType = iota
	KeyModified      KeyChangeType = iota
)

type KeyChange struct {
	Fingerprint    string
	CurrentMd5     string
	PreviousMd5    string
	CurrentSha256  string
	PreviousSha256 string
	Error          error
	Type           KeyChangeType
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
	case KeyNotChanged:
		msg = fmt.Sprintf("No change in key %s", kc.Fingerprint)
	}
	w.Write([]byte(msg))
	if kc.Error != nil {
		w.Write([]byte(fmt.Sprintf(": Error: %v", kc.Error)))
	}
	return w.String()
}

func (change *KeyChange) calcType() KeyChangeType {
	if change.CurrentSha256 == "" {
		return KeyChangeInvalid
	} else if change.PreviousSha256 == "" {
		return KeyAdded
	} else if change.PreviousSha256 == change.CurrentSha256 {
		return KeyNotChanged
	}
	return KeyModified
}

func (w *Worker) UpsertKey(key *Pubkey) (change *KeyChange) {
	change = &KeyChange{Fingerprint: key.Fingerprint(), Type: KeyChangeInvalid}
	lastKey, err := w.LookupKey(key.Fingerprint())
	if err == hockeypuck.ErrKeyNotFound {
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
	switch change.Type {
	case KeyModified:
		lastKey.Mtime = time.Now()
		change.Error = w.UpdateKey(lastKey)
	case KeyAdded:
		key.Ctime = time.Now()
		key.Mtime = key.Ctime
		change.Error = w.InsertKey(key)
	}
	log.Println(change)
	return
}

func (w *Worker) UpdateKey(pubkey *Pubkey) error {
	panic("not impl yet")
}

func (w *Worker) InsertKey(pubkey *Pubkey) error {
	panic("not impl yet")
}
