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

package hockeypuck

import (
	"code.google.com/p/gorilla/mux"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/cmars/conflux/recon"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// HTTP bind address option
func init() { flag.String("http", ":11371", "http bind address") }
func (s *Settings) HttpBind() string {
	return s.GetString("http")
}

// Create a new HKP server on the given Gorilla mux router.
func NewHkpServer(r *mux.Router) *HkpServer {
	hkp := &HkpServer{
		LookupRequests: make(LookupChan, HKP_CHAN_SIZE),
		AddRequests:    make(AddChan, HKP_CHAN_SIZE)}
	r.HandleFunc("/",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.index(resp, req)
		})
	r.HandleFunc("/add",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.addForm(resp, req)
		})
	r.HandleFunc(`/css/{filename:.*\.css}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
			path := filepath.Join(Config().Webroot(), "css", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
				http.NotFound(resp, req)
				return
			}
			http.ServeFile(resp, req, path)
		})
	r.HandleFunc(`/fonts/{filename:.*\.ttf}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
			path := filepath.Join(Config().Webroot(), "fonts", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
				http.NotFound(resp, req)
				return
			}
			http.ServeFile(resp, req, path)
		})
	r.HandleFunc("/pks/lookup",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.lookup(resp, req)
		})
	r.HandleFunc("/pks/hashquery",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.hashQuery(resp, req)
		})
	r.HandleFunc("/pks/add",
		func(resp http.ResponseWriter, req *http.Request) {
			hkp.add(resp, req)
		})
	return hkp
}

// Handle lookup HTTP requests
func (hkp *HkpServer) lookup(respWriter http.ResponseWriter, req *http.Request) error {
	// build Lookup from query arguments
	lookup, err := parseLookup(req)
	if err != nil {
		respError(respWriter, err)
		return err
	}
	hkp.LookupRequests <- lookup
	return respondWith(respWriter, lookup)
}

// Handle SKS hashquery HTTP requests
func (hkp *HkpServer) hashQuery(respWriter http.ResponseWriter, req *http.Request) error {
	// Parse hashquery POST
	defer req.Body.Close()
	n, err := recon.ReadInt(req.Body)
	if err != nil {
		return err
	}
	log.Println("hashquery:", n, "keys requested")
	searchDigests := make([]string, n)
	for i := 0; i < n; i++ {
		hashlen, err := recon.ReadInt(req.Body)
		if err != nil {
			return err
		}
		hash := make([]byte, hashlen)
		_, err = req.Body.Read(hash)
		if err != nil {
			return err
		}
		searchDigests[i] = hex.EncodeToString(hash)
	}
	log.Println("hashquery:", searchDigests, "requested")
	lookup := &Lookup{responseChan: make(chan Response),
		Op: HashQuery, Search: strings.Join(searchDigests, ",")}
	hkp.LookupRequests <- lookup
	respWriter.Header().Set("Content-Type", "pgp/keys")
	return respondWith(respWriter, lookup)
}

// Write a server error response
func respError(respWriter http.ResponseWriter, err error) error {
	respWriter.WriteHeader(500)
	_, writeErr := respWriter.Write([]byte(err.Error()))
	return writeErr
}

// Parse the lookup request into a model.
func parseLookup(req *http.Request) (*Lookup, error) {
}

// Parse the value of the "options" variable (section 3.2.1)
// into a model.
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

// Handle add HTTP requests
func (hkp *HkpServer) add(respWriter http.ResponseWriter, req *http.Request) error {
	add, err := parseAdd(req)
	if err != nil {
		respError(respWriter, err)
		return err
	}
	hkp.AddRequests <- add
	return respondWith(respWriter, add)
}

// Parse the add request into a model.
func parseAdd(req *http.Request) (*Add, error) {
	// Require HTTP POST
	if req.Method != "POST" {
		return nil, errors.New(fmt.Sprintf("Invalid method for add: %s", req.Method))
	}
	// Parse the URL query parameters
	err := req.ParseForm()
	if err != nil {
		return nil, err
	}
	add := &Add{responseChan: make(chan Response)}
	if keytext := req.Form.Get("keytext"); keytext == "" {
		return nil, errors.New("Missing required parameter: op")
	} else {
		add.Keytext = keytext
	}
	add.Option = parseOptions(req.Form.Get("options"))
	return add, nil
}

// Receive a response and write it to the client
func respondWith(respWriter http.ResponseWriter, r HasResponse) error {
	response := <-r.Response()
	if err := response.Error(); err != nil {
		respWriter.WriteHeader(500)
		respWriter.Write([]byte(err.Error()))
		return nil
	}
	return response.WriteTo(respWriter)
}

func (hkp *HkpServer) index(respWriter http.ResponseWriter, req *http.Request) error {
	return SearchFormTemplate.ExecuteTemplate(respWriter, "layout", nil)
}

func (hkp *HkpServer) addForm(respWriter http.ResponseWriter, req *http.Request) error {
	return AddFormTemplate.ExecuteTemplate(respWriter, "layout", nil)
}
