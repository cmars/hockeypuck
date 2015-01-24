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
	"net/http"

	"github.com/gorilla/mux"
	log "gopkg.in/hockeypuck/logrus.v0"

	"github.com/hockeypuck/hockeypuck"
)

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
		log.Errorf("error parsing request %+v: %q", req, err)
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}
	r.Requests <- req
	resp := <-req.Response()
	if resp.Error() != nil {
		log.Errorf("failed to responsd: %v", resp.Error())
	}
	err = resp.WriteTo(w)
	if err != nil {
		log.Errorf("failed to write response: %v", err)
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
				err = hockeypuck.ErrTemplatePathNotFound
			} else {
				err = AddFormTemplate.ExecuteTemplate(w, "layout", nil)
			}
			if err != nil {
				http.Error(w, "application templates not found", http.StatusInternalServerError)
			}
		})
	r.HandleFunc("/openpgp/lookup",
		func(w http.ResponseWriter, req *http.Request) {
			var err error
			if SearchFormTemplate == nil {
				err = hockeypuck.ErrTemplatePathNotFound
			} else {
				err = SearchFormTemplate.ExecuteTemplate(w, "layout", nil)
			}
			if err != nil {
				http.Error(w, "application templates not found", http.StatusInternalServerError)
			}
		})
}
