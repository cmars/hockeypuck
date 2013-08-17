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
	"github.com/stretchr/testify/assert"
	"launchpad.net/hockeypuck"
	"testing"
)

func TestBadSelfSigUid(t *testing.T) {
	key := MustInputAscKey(t, "badselfsig.asc")
	kv := ValidateKey(key)
	t.Log(kv)
}

func TestStrictV3(t *testing.T) {
	f := MustInput(t, "sigv3.gpg")
	defer f.Close()
	defer hockeypuck.SetConfig("")
	Config().Set("hockeypuck.openpgp.strict", true)
	assert.True(t, Config().GetBool("hockeypuck.openpgp.strict"))
	for _ = range ReadValidKeys(f) {
		t.Fatal("v3 sig should not validate in strict mode (until we support them)")
	}
}

/*
	armorBlock, err := armor.Decode(bytes.NewBufferString(armoredKey))
	assert.Equal(t, nil, err)
	keyChan, errChan := ReadValidKeys(armorBlock.Body)
READING:
	for {
		select {
		case key, ok := <-keyChan:
			if !ok {
				break READING
			}
			t.Errorf("Should not get a key %v -- it's not valid", key)
		case err, ok := <-errChan:
			if !ok {
				break READING
			}
			t.Log(err)
		}
	}
}
*/
