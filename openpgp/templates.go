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

package openpgp

import (
	"flag"
	"go/build"
	"html/template"
	"os"
	"path/filepath"
	"time"
)

const INSTALL_WEBROOT = "/var/lib/hockeypuck/www"
const HOCKEYPUCK_PKG = "launchpad.net/hockeypuck" // Any way to introspect?

// Path to Hockeypuck's installed www directory
func init() {
	flag.String("webroot", "",
		"Location of static web server files and templates")
}
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

// SearchFormTemplate is used to render the default search form at '/'
var SearchFormTemplate *template.Template

// AddFormTemplate is used to render the form to add a key.
var AddFormTemplate *template.Template

// AddResultTemplate displays the fingerprints of updated keys.
var AddResultTemplate *template.Template

// PksIndexTemplate is used to render the op=index and op=vindex
// responses when not in machine readable mode.
var PksIndexTemplate *template.Template

// StatsTemplate renders the op=stats page
var StatsTemplate *template.Template

func InitTemplates(path string) {
	SearchFormTemplate = newSearchFormTemplate(path)
	AddFormTemplate = newAddFormTemplate(path)
	AddResultTemplate = newAddResultTemplate(path)
	PksIndexTemplate = newPksIndexTemplate(path)
	StatsTemplate = newStatsTemplate(path)
	return
}

func newSearchFormTemplate(path string) *template.Template {
	files, _ := filepath.Glob(filepath.Join(path, "templates", "*.tmpl"))
	files = append(files,
		filepath.Join(path, "templates", "index", "search_form.tmpl"))
	return template.Must(template.ParseFiles(files...))
}

func newAddFormTemplate(path string) *template.Template {
	files, _ := filepath.Glob(filepath.Join(path, "templates", "*.tmpl"))
	files = append(files,
		filepath.Join(path, "templates", "add", "add_form.tmpl"))
	return template.Must(template.ParseFiles(files...))
}

func newAddResultTemplate(path string) *template.Template {
	files, _ := filepath.Glob(filepath.Join(path, "templates", "*.tmpl"))
	files = append(files,
		filepath.Join(path, "templates", "add", "add_result.tmpl"))
	return template.Must(template.ParseFiles(files...))
}

func newPksIndexTemplate(path string) *template.Template {
	files, _ := filepath.Glob(filepath.Join(path, "templates", "*.tmpl"))
	files = append(files,
		filepath.Join(path, "templates", "pks", "index.tmpl"))
	return template.Must(template.ParseFiles(files...))
}

func newStatsTemplate(path string) *template.Template {
	files, _ := filepath.Glob(filepath.Join(path, "templates", "*.tmpl"))
	files = append(files,
		filepath.Join(path, "templates", "pks", "stats.tmpl"))
	return template.Must(template.New("placeholder").Funcs(
		template.FuncMap{"timef": func(ts int64) string {
			tm := time.Unix(0, ts)
			return tm.Format(time.RFC3339)
		}}).ParseFiles(files...))
}
