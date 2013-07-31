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
	"html/template"
	"launchpad.net/hockeypuck"
	"log"
	"path/filepath"
	"time"
)

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

func InitTemplates() {
	SearchFormTemplate = tryTemplate(newSearchFormTemplate)
	AddFormTemplate = tryTemplate(newAddFormTemplate)
	AddResultTemplate = tryTemplate(newAddResultTemplate)
	PksIndexTemplate = tryTemplate(newPksIndexTemplate)
	StatsTemplate = tryTemplate(newStatsTemplate)
}

func templateFiles(relPath ...string) []string {
	basePath := filepath.Join(hockeypuck.Config().Webroot(), "templates")
	files, _ := filepath.Glob(filepath.Join(basePath, "*.tmpl"))
	return append(files, filepath.Join(append([]string{
		hockeypuck.Config().Webroot(), "templates", "hkp"}, relPath...)...))
}

type templateFactory func() (*template.Template, error)

func tryTemplate(fn templateFactory) *template.Template {
	tmpl, err := fn()
	if err != nil {
		log.Println(err)
		return nil
	}
	return tmpl
}

func newSearchFormTemplate() (*template.Template, error) {
	return template.ParseFiles(templateFiles("index", "search_form.tmpl")...)
}

func newAddFormTemplate() (*template.Template, error) {
	return template.ParseFiles(templateFiles("add", "add_form.tmpl")...)
}

func newAddResultTemplate() (*template.Template, error) {
	return template.ParseFiles(templateFiles("add", "add_result.tmpl")...)
}

func newPksIndexTemplate() (*template.Template, error) {
	return template.ParseFiles(templateFiles("pks", "index.tmpl")...)
}

func newStatsTemplate() (*template.Template, error) {
	return template.New("placeholder").Funcs(
		template.FuncMap{"timef": func(ts int64) string {
			tm := time.Unix(0, ts)
			return tm.Format(time.RFC3339)
		}}).ParseFiles(templateFiles("pks", "stats.tmpl")...)
}
