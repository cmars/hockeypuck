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
	"net/http"
	"net/url"
	"testing"
	"github.com/bmizerany/assert"
)

func TestParseLookup(t *testing.T) {
	testUrl, err := url.Parse("/pks/lookup?op=get&search=alice")
	assert.Equal(t, err, nil)
	req := &http.Request{
		Method: "GET",
		URL: testUrl }
	lookup, err := parseLookup(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, Get, lookup.Op)
	assert.Equal(t, "alice", lookup.Search)
	assert.Equal(t, NoOption, lookup.Option)
	assert.Equal(t, false, lookup.Fingerprint)
	assert.Equal(t, false, lookup.Exact)
}

func TestParseAdd(t *testing.T) {
	testUrl, err := url.Parse("/pks/add")
	assert.Equal(t, err, nil)
	postData := make(map[string][]string)
	postData["keytext"] = []string{ "sus llaves aqui" }
	req := &http.Request{
		Method: "POST",
		URL: testUrl,
		Form: url.Values(postData) }
	add, err := parseAdd(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, "sus llaves aqui", add.Keytext)
	assert.Equal(t, NoOption, add.Option)
}
