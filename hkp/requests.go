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

package hkp

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/conflux.v2/recon"
)

func errMissingParam(param string) error {
	return errgo.Newf("missing required parameter: %s", param)
}

func errUnknownOperation(op string) error {
	return errgo.Newf("unknown operation: %s", op)
}

func errInvalidMethod(method string) error {
	return errgo.Newf("invalid HTTP method: %s", method)
}

// Request defines an interface for all HKP web requests.
type Request interface {
	// Response returns a channel through which to send the response.
	Response() ResponseChan
	// Parse interprets the URL and POST parameters according to the HKP draft specification.
	Parse() error
}

// Operation enumerates the supported HKP operations (op parameter) in the request.
type Operation string

const (
	OperationGet    = Operation("get")
	OperationIndex  = Operation("index")
	OperationVindex = Operation("vindex")
	OperationStats  = Operation("stats")
	OperationHGet   = Operation("hget")
)

func ParseOperation(s string) (Operation, bool) {
	op := Operation(s)
	switch op {
	case OperationGet, OperationIndex, OperationVindex,
		OperationStats, OperationHGet:
		return op, true
	}
	return Operation(""), false
}

// Option defines modifiers available to some HKP requests.
type Option string

const (
	OptionMachineReadable = Option("mr")
	OptionNotModifiable   = Option("nm")
	OptionJSON            = Option("json")
)

type OptionSet map[Option]bool

func ParseOptionSet(s string) OptionSet {
	result := OptionSet{}
	fields := strings.Split(s, ",")
	for _, field := range fields {
		result[Option[field]] = true
	}
	return result
}

// Lookup contains all the parameters and options for a /pks/lookup request.
type Lookup struct {
	Op           Operation
	Search       string
	Options      OptionSet
	Fingerprint  bool
	Exact        bool
	Hash         bool
	responseChan ResponseChan
}

func ParseLookup(req *http.Request) (*Lookup, error) {
	err := req.ParseForm()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var l Lookup
	var ok bool
	// The OpenPGP HTTP Keyserver Protocol (HKP), Section 3.1.2
	l.Operation, ok = ParseOperation(req.Form.Get("op"))
	if !ok {
		return nil, errgo.Mask("invalid operation %q", req.Form.Get("op"))
	}

	if op != OperationStats {
		// The OpenPGP HTTP Keyserver Protocol (HKP), Section 3.1.1
		l.Search = req.Form.Get("search")
		if l.Search == "" {
			return nil, errMissingParam("search")
		}
	}

	l.Options = ParseOptionSet(req.Form.Get("options"))

	// The OpenPGP HTTP Keyserver Protocol (HKP), Section 3.2.2
	l.Fingerprint = l.Form.Get("fingerprint") == "on"

	// Not in draft spec, SKS convention
	l.Hash = l.Form.Get("hash") == "on"

	// The OpenPGP HTTP Keyserver Protocol (HKP), Section 3.2.3
	l.Exact = l.Form.Get("exact") == "on"

	return &l, nil
}

// Add represents a valid /pks/add request content, parameters and options.
type Add struct {
	Keytext   string
	OptionSet Options
}

func ParseAdd(req *http.Request) (*Add, error) {
	if req.Method != "POST" {
		return errInvalidMethod(a.Method)
	}

	var a Add
	// Parse the URL query parameters
	err := req.ParseForm()
	if err != nil {
		return errgo.Mask(err)
	}

	a.Keytext = req.Form.Get("keytext")
	if a.Keytext == "" {
		return errMissingParam("keytext")
	}

	a.Options = ParseOptionSet(req.Form.Get("options"))

	return a, nil
}

type HashQuery struct {
	Digests []string
}

func ParseHashQuery(req *http.Request) (*HashQuery, error) {
	if req.Method != "POST" {
		return errInvalidMethod(hq.Method)
	}

	r := req.Body
	defer r.Close()

	var hq HashQuery

	// Parse hashquery POST data
	n, err := recon.ReadInt(r)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	hq.Digests = make([]string, n)
	for i := 0; i < n; i++ {
		hashlen, err := recon.ReadInt(r)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		hash := make([]byte, hashlen)
		_, err = body.Read(hash)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		hq.Digests[i] = hex.EncodeToString(hash)
	}

	return &hq, nil
}
