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
)

// Size of the worker channels. May want to make this configurable.
const HKP_CHAN_SIZE = 20

// Operation type in request
type Operation int

const (
	Get Operation = 1
	Index Operation = iota
	Vindex Operation = iota
	UnknownOperation = 0
)

// Supported HKP options
type Option int

const (
	MachineReadable Option = 1 << iota
	NotModifiable Option = 1 << iota
	UnknownOption = 0
)

// An HKP "lookup" request
type Lookup struct {
	Op Operation
	Search string
	Option Option
	Fingerprint bool
	Exact bool
	responseChan ResponseChan
}

func (l *Lookup) Response() ResponseChan {
	return l.responseChan
}

// An HKP "add" posting.
type Add struct {
	Keytext string
	Option Option
	responseChan ResponseChan
}

func (a *Add) Response() ResponseChan {
	return a.responseChan
}

// Interface for requests that have a response channel
type HasResponse interface {
	Response() ResponseChan
}

// Worker responses
type Response interface {
	Error() error
	WriteTo(http.ResponseWriter) error
}

// Channel of Lookup requests, to be read by a lookup worker
type LookupChan chan *Lookup

// Channel of Add requests, to be read by an add worker
type AddChan chan *Add

// Response channel written by the workers
type ResponseChan chan Response

// The HKP server
type HkpServer struct {
	LookupRequests LookupChan
	AddRequests AddChan
}
