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
	"log"
	"net/http"

	"code.google.com/p/gorilla/mux"

	"github.com/cmars/hockeypuck"
	Errors "github.com/cmars/hockeypuck/errors"
)

func (s *Settings) HttpBind() string {
	return s.GetStringDefault("hockeypuck.hkp.bind", ":11371")
}

type Service struct {
	Requests RequestChan
}

func NewService() *Service {
	return &Service{make(RequestChan)}
}

type Router struct {
	*mux.Router
	*Service
}

func NewRouter(r *mux.Router) *Router {
	hkpr := &Router{Router: r, Service: NewService()}
	hkpr.HandleAll()
	return hkpr
}

func (r *Router) HandleAll() {
	r.HandleWebUI()
	r.HandlePksLookup()
	r.HandlePksAdd()
	r.HandlePksHashQuery()
}

func (r *Router) Respond(w http.ResponseWriter, req Request) {
	err := req.Parse()
	if err != nil {
		log.Println("Error parsing request:", err)
		http.Error(w, hockeypuck.APPLICATION_ERROR, 400)
		return
	}
	r.Requests <- req
	resp := <-req.Response()
	if resp.Error() != nil {
		log.Println("Error in response:", resp.Error())
	}
	err = resp.WriteTo(w)
	if err != nil {
		log.Println(resp, err)
	}
}

func (r *Router) HandlePksLookup() {
	r.HandleFunc("/pks/lookup",
		func(w http.ResponseWriter, req *http.Request) {
			r.Respond(w, &Lookup{Request: req})
		})
}

func (r *Router) HandlePksAdd() {
	r.HandleFunc("/pks/add",
		func(w http.ResponseWriter, req *http.Request) {
			r.Respond(w, &Add{Request: req})
		})
}

func (r *Router) HandlePksHashQuery() {
	r.HandleFunc("/pks/hashquery",
		func(w http.ResponseWriter, req *http.Request) {
			r.Respond(w, &HashQuery{Request: req})
		})
}

func (r *Router) HandleWebUI() {
	r.HandleFunc("/openpgp/add",
		func(w http.ResponseWriter, req *http.Request) {
			var err error
			if SearchFormTemplate == nil {
				err = Errors.ErrTemplatePathNotFound
			} else {
				err = AddFormTemplate.ExecuteTemplate(w, "layout", nil)
			}
			if err != nil {
				http.Error(w, hockeypuck.APPLICATION_ERROR, 500)
			}
		})
	r.HandleFunc("/openpgp/lookup",
		func(w http.ResponseWriter, req *http.Request) {
			var err error
			if SearchFormTemplate == nil {
				err = Errors.ErrTemplatePathNotFound
			} else {
				err = SearchFormTemplate.ExecuteTemplate(w, "layout", nil)
			}
			if err != nil {
				http.Error(w, hockeypuck.APPLICATION_ERROR, 500)
			}
		})
}
