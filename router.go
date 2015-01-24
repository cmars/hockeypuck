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

package hockeypuck

import (
	"flag"
	//"go/build"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
)

// System installed location for static files.
const INSTALL_WEBROOT = "/var/lib/hockeypuck/www"

// Hockeypuck package, used to locate static files when running from source.
const HOCKEYPUCK_PKG = "github.com/hockeypuck/hockeypuck" // Any way to introspect?

// Response for HTTP 500.
const APPLICATION_ERROR = "APPLICATION ERROR"

// Response for HTTP 400.
const BAD_REQUEST = "BAD REQUEST"

// Path to Hockeypuck's installed www directory
func init() {
	flag.String("webroot", "",
		"Location of static web server files and templates")
}

/*
func (s *Settings) Webroot() string {
	webroot := s.GetString("webroot")
	if webroot != "" {
		return webroot
	}
	if fi, err := os.Stat(INSTALL_WEBROOT); err == nil && fi.IsDir() {
		webroot = INSTALL_WEBROOT
	} else if p, err := build.Default.Import(HOCKEYPUCK_PKG, "", build.FindOnly); err == nil {
		try_webroot := filepath.Join(p.Dir, "instroot", INSTALL_WEBROOT)
		if fi, err := os.Stat(try_webroot); err == nil && fi.IsDir() {
			webroot = try_webroot
		}
	}
	s.Set("webroot", webroot)
	return webroot
}
*/

// StaticRouter configures HTTP request handlers for static media files.
type StaticRouter struct {
	*mux.Router
	settings *Settings
}

// NewStaticRouter constructs a new static media router and sets up all request handlers.
func NewStaticRouter(r *mux.Router, s *Settings) *StaticRouter {
	sr := &StaticRouter{Router: r, settings: s}
	sr.HandleAll()
	return sr
}

// HandleAll sets up all request handlers for Hockeypuck static media.
func (sr *StaticRouter) HandleAll() {
	sr.HandleMainPage()
	sr.HandleFonts()
	sr.HandleCss()
}

// HandleMainPage handles the "/" top-level request.
func (sr *StaticRouter) HandleMainPage() {
	sr.HandleFunc("/",
		func(resp http.ResponseWriter, req *http.Request) {
			http.Redirect(resp, req, "/openpgp/lookup", http.StatusMovedPermanently)
		})
}

// HandleFonts handles all embedded web font requests.
func (sr *StaticRouter) HandleFonts() {
	sr.HandleFunc(`/fonts/{filename:.*\.ttf}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
			path := filepath.Join(sr.settings.Webroot, "fonts", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
				http.NotFound(resp, req)
				return
			}
			http.ServeFile(resp, req, path)
		})
}

// HandleCSS handles all embedded cascading style sheet (CSS) requests.
func (sr *StaticRouter) HandleCss() {
	sr.HandleFunc(`/css/{filename:.*\.css}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
			path := filepath.Join(sr.settings.Webroot, "css", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
				http.NotFound(resp, req)
				return
			}
			http.ServeFile(resp, req, path)
		})
}
