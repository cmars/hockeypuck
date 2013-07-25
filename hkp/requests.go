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

package hkp

import (
	"fmt"
	"github.com/cmars/conflux/recon"
	"log"
	"net/http"
)

func ErrorMissingParam(param string) error {
	return errors.New(fmt.Sprintf("Missing required parameter: %s", param))
}

func ErrorUnknownOperation(op string) error {
	return errors.New(fmt.Sprintf("Unknown operation: %s", op))
}

func ErrorInvalidMethod(method string) error {
	errors.New(fmt.Sprintf("Invalid HTTP method: %s", method))
}

type Request interface {
	Response() ResponseChan
	Parse() error
}

// Operation type in request.
type Operation int

// Hockeypuck supported Operations.
const (
	UnknownOperation           = iota
	Get              Operation = iota
	Index            Operation = iota
	Vindex           Operation = iota
	Stats            Operation = iota
	HashGet          Operation = iota
)

// Option bit mask in request.
type Option int

// Hockeypuck supported HKP options.
const (
	MachineReadable Option = 1 << iota
	NotModifiable   Option = 1 << iota
	JsonFormat      Option = 1 << iota
	NoOption               = Option(0)
)

// An HKP "lookup" request.
type Lookup struct {
	*http.Request
	Op           Operation
	Search       string
	Option       Option
	Fingerprint  bool
	Exact        bool
	responseChan ResponseChan
}

// Get the response channel that a worker processing
// a lookup request will use to send the response back to the
// web server.
func (l *Lookup) Response() ResponseChan {
	return l.responseChan
}

func (l *Lookup) Parse() (err error) {
	// Parse the URL query parameters
	err = l.ParseForm()
	if err != nil {
		return
	}
	l.responseChan = make(ResponseChan)
	searchRequired := true
	// Parse the "op" variable (section 3.1.2)
	switch op := l.Form.Get("op"); op {
	case "get":
		l.Op = Get
	case "index":
		l.Op = Index
	case "vindex":
		l.Op = Vindex
	case "stats":
		l.Op = Stats
		searchRequired = false
	case "hget":
		l.Op = HashGet
	case "":
		return ErrorMissingParam("op")
	default:
		return ErrorUnknownOperation(op)
	}
	// Parse the "search" variable (section 3.1.1)
	if l.Search = l.Form.Get("search"); searchRequired && lookup.Search == "" {
		return ErrorMissingParam("search")
	}
	// Parse the "options" variable (section 3.2.1)
	l.Option = parseOptions(req.Form.Get("options"))
	// Parse the "fingerprint" variable (section 3.2.2)
	l.Fingerprint = l.Form.Get("fingerprint") == "on"
	// Parse the "exact" variable (section 3.2.3)
	l.Exact = l.Form.Get("exact") == "on"
	return err
}

// parseOptions interprets the "options" parameter (section 3.2.1)
func parseOptions(options string) Option {
	var result Option
	optionValues := strings.Split(options, ",")
	for _, option := range optionValues {
		switch option {
		case "mr":
			result |= MachineReadable
		case "nm":
			result |= NotModifiable
		case "json":
			result |= JsonFormat
		}
	}
	return result
}

// An HKP "add" request.
type Add struct {
	*http.Request
	Keytext      string
	Option       Option
	responseChan ResponseChan
}

// Get the response channel for sending a response to an add request.
func (a *Add) Response() ResponseChan {
	return a.responseChan
}

func (a *Add) Parse() (err error) {
	// Require HTTP POST
	if a.Method != "POST" {
		return ErrorInvalidMethod(a.Method)
	}
	// Parse the URL query parameters
	err = a.ParseForm()
	if err != nil {
		return err
	}
	a.responseChan = make(ResponseChan)
	if keytext := a.Form.Get("keytext"); keytext == "" {
		return nil, ErrorMissingParam("keytext")
	} else {
		add.Keytext = keytext
	}
	add.Option = parseOptions(a.Form.Get("options"))
	return add, nil
}

type HashQuery struct {
	*http.Request
	Digests      []string
	responseChan ResponseChan
}

func (hq *HashQuery) Response() ResponseChan {
	return hq.responseChan
}

func (hq *HashQuery) Parse() error {
	// Require HTTP POST
	if hq.Method != "POST" {
		return ErrorInvalidMethod(hq.Method)
	}
	// Parse hashquery POST data
	defer hq.Body.Close()
	n, err := recon.ReadInt(hq.Body)
	if err != nil {
		return err
	}
	hq.Digests = make([]string, n)
	for i := 0; i < n; i++ {
		hashlen, err := recon.ReadInt(hq.Body)
		if err != nil {
			return err
		}
		hash := make([]byte, hashlen)
		_, err = hq.Body.Read(hash)
		if err != nil {
			return err
		}
		hq.Digests[i] = hex.EncodeToString(hash)
	}
	return nil
}

// Worker responses.
type Response interface {
	Error() error
	WriteTo(http.ResponseWriter) error
}

// Channel of HKP requests, to be read by a worker.
type RequestChan chan Request

// Response channel to which the workers send their results.
type ResponseChan chan Response
