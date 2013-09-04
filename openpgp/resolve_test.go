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
	"strings"
	"testing"
)

func TestBadSelfSigUid(t *testing.T) {
	key := MustInputAscKey(t, "badselfsig.asc")
	Resolve(key)
	for _, uid := range key.userIds {
		assert.True(t, !strings.Contains(uid.UserId.Id, "Karneef"))
	}
}

func TestStrictV3(t *testing.T) {
	f := MustInput(t, "sigv3.gpg")
	defer f.Close()
	defer hockeypuck.SetConfig("")
	for k := range ReadKeys(f) {
		t.Log(k)
	}
}
