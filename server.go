package hockeypuck

import (
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
	responseChan ResponseChan
}

func (l *Lookup) Response() ResponseChan {
	return l.responseChan
}

type Add struct {
	Keytext string
	Options int
	responseChan ResponseChan
}

func (a *Add) Response() ResponseChan {
	return a.responseChan
}

type HasResponse interface {
	Response() ResponseChan
}

type Response interface {
	Error() error
	WriteTo(http.ResponseWriter) error
}

type LookupChan chan *Lookup

type AddChan chan *Add

type ResponseChan chan Response

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

func (hkp *HkpServer) lookup(respWriter http.ResponseWriter, req *http.Request) error {
	// build Lookup from query arguments
	lookup, err := hkp.newLookup(req)
	if err != nil {
		return nil
	}
	hkp.LookupRequests <- lookup
	return hkp.respondWith(respWriter, lookup)
}

func (hkp *HkpServer) newLookup(req *http.Request) (*Lookup, error) {
	panic("todo")
}

func (hkp *HkpServer) add(respWriter http.ResponseWriter, req *http.Request) error {
	// build Lookup from query arguments
	add, err := hkp.newAdd(req)
	if err != nil {
		return nil
	}
	hkp.AddRequests <- add
	return hkp.respondWith(respWriter, add)
}

func (hkp *HkpServer) newAdd(req *http.Request) (*Add, error) {
	panic("todo")
}

func (hkp *HkpServer) respondWith(respWriter http.ResponseWriter, r HasResponse) error {
	response := <-r.Response()
	if err := response.Error(); err != nil {
		return err
	}
	return response.WriteTo(respWriter)
}
