package hockeypuck

import (
	"errors"
	"net/http"
	"code.google.com/p/gorilla/mux"
)

const HKP_CHAN_SIZE = 20

type Operation int

const (
	Get Operation = 1 << iota
	Index Operation = 1 << iota
	Vindex Operation = 1 << iota
)

type Option int

const (
	MachineReadable Option = 1 << iota
	NotModifiable Option = 1 << iota
)

type Lookup struct {
	Op Operation
	Search string
	Options int
	Fingerprint bool
	Exact bool
	// chan to some kind of response object
}

type Add struct {
	Keytext string
	Options int
	// chan to some kind of response object
}

type LookupChan chan *Lookup

type AddChan chan *Add

type HkpServer struct {
	LookupRequests LookupChan
	AddRequests AddChan
}

func NewHkpServer(r *mux.Router) *HkpServer {
	hkp := &HkpServer{
		LookupRequests: make(LookupChan, HKP_CHAN_SIZE),
		AddRequests: make(AddChan, HKP_CHAN_SIZE) }
	r.HandleFunc("/pks/lookup",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.lookup(resp, req) })
	r.HandleFunc("/pks/add",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.add(resp, req) })
	return hkp
}

func (hkp *HkpServer) lookup(resp http.ResponseWriter, req *http.Request) error {
	// build Lookup from query arguments
	lookup := &Lookup{}
	hkp.LookupRequests <- lookup
/*
	result := <-lookup.Response
	// write response
	result.WriteTo(resp)
*/
	return errors.New("not impl")
}

func (hkp *HkpServer) add(resp http.ResponseWriter, req *http.Request) error {
	// build Add from query arguments
	add := &Add{}
	hkp.AddRequests <- add
/*
	result := <-add.Response
	// write response
	result.WriteTo(resp)
*/
	return errors.New("not impl")
}
