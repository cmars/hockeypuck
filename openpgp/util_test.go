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
	"code.google.com/p/go.crypto/openpgp/armor"
	"launchpad.net/hockeypuck"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func init() {
	hockeypuck.SetConfig("")
}

func MustInput(t *testing.T, name string) *os.File {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Cannot locate unit test data files")
	}
	path := filepath.Join(filepath.Dir(thisFile), "testdata", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("Cannot open unit test data file", path, ":", err)
	}
	return f
}

func MustInputAscKeys(t *testing.T, name string) (result []*Pubkey) {
	f := MustInput(t, name)
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	for keyRead := range ReadKeys(block.Body) {
		if keyRead.Error != nil {
			t.Fatal(keyRead.Error)
		}
		result = append(result, keyRead.Pubkey)
	}
	return
}

func MustInputAscKey(t *testing.T, name string) *Pubkey {
	keys := MustInputAscKeys(t, name)
	if len(keys) != 1 {
		t.Fatal("Expected only one key, got", len(keys))
	}
	return keys[0]
}
