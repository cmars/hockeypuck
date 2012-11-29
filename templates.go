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
	"flag"
	"html/template"
	"path/filepath"
	"time"
)

// Path to Hockeypuck's installed www directory
var WwwRoot *string = flag.String("www-root",
	"/var/lib/hockeypuck/www",
	"Location of static web server files and templates")

var wwwRoot string

// SearchFormTemplate is used to render the default search form at '/'
var SearchFormTemplate *template.Template

// AddFormTemplate is used to render the form to add a key.
var AddFormTemplate *template.Template

// AddResultTemplate displays the fingerprints of updated keys.
var AddResultTemplate *template.Template

// PksIndexTemplate is used to render the op=index and op=vindex
// responses when not in machine readable mode.
var PksIndexTemplate *template.Template

// StatusTemplate renders the op=status page
var StatusTemplate *template.Template

func InitTemplates(path string) {
	wwwRoot, _ = filepath.Abs(path)
	SearchFormTemplate = newSearchFormTemplate(path)
	AddFormTemplate = newAddFormTemplate(path)
	AddResultTemplate = newAddResultTemplate(path)
	PksIndexTemplate = newPksIndexTemplate(path)
	StatusTemplate = newStatusTemplate(path)
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

func newStatusTemplate(path string) *template.Template {
	files, _ := filepath.Glob(filepath.Join(path, "templates", "*.tmpl"))
	files = append(files,
		filepath.Join(path, "templates", "pks", "status.tmpl"))
	return template.Must(template.New("placeholder").Funcs(
		template.FuncMap{"timef": func(ts int64) string {
			tm := time.Unix(0, ts)
			return tm.Format(time.RFC3339)
		}}).ParseFiles(files...))
}
