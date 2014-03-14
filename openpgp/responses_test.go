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
	"bytes"
	"crypto/md5"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cmars/conflux/recon"
	"github.com/stretchr/testify/assert"

	"github.com/hockeypuck/hockeypuck/hkp"
)

func TestHashqueryResponse(t *testing.T) {
	key := MustInputAscKey(t, "uat.asc")
	resp := HashQueryResponse{[]*Pubkey{key}}
	rec := httptest.NewRecorder()
	err := resp.WriteTo(rec)
	assert.Nil(t, err)
	assert.Equal(t, 200, rec.Code)
}

func TestHashqueryRequest(t *testing.T) {
	key := MustInputAscKey(t, "uat.asc")
	// Determine reference digest to compare with
	h := md5.New()
	refDigestStr := SksDigest(key, h)
	refDigest := h.Sum(nil)
	// Parse url for request
	url, err := url.Parse("/pks/hashquery")
	assert.Nil(t, err)
	// hashquery contents (sks recon wire protocol)
	var buf bytes.Buffer
	err = recon.WriteInt(&buf, 1)
	assert.Nil(t, err)
	err = recon.WriteInt(&buf, len(refDigest))
	assert.Nil(t, err)
	_, err = buf.Write(refDigest)
	assert.Nil(t, err)
	// Create an HTTP request
	req := &http.Request{
		Method: "POST",
		URL:    url,
		Body:   ioutil.NopCloser(bytes.NewBuffer(buf.Bytes())),
	}
	// Parse it
	hq := hkp.NewHashQuery()
	hq.Request = req
	err = hq.Parse()
	assert.Nil(t, err)
	assert.Equal(t, refDigestStr, hq.Digests[0])
	t.Log(hq.Digests)
}
