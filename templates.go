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
//	"fmt"
	"html/template"
//	"os"
	"path/filepath"
)

var WwwRoot string

// SearchFormTemplate is used to render the default search form at '/'
var SearchFormTemplate *template.Template

// PksIndexTemplate is used to render the op=index and op=vindex
// responses when not in machine readable mode.
var PksIndexTemplate *template.Template

func InitTemplates(path string) {
	WwwRoot, _ = filepath.Abs(path)
	SearchFormTemplate = newSearchFormTemplate(path)
	PksIndexTemplate = newPksIndexTemplate(path)
	return
}

func newSearchFormTemplate(path string) *template.Template {
	files, _ := filepath.Glob(filepath.Join(path, "templates", "*.tmpl"))
	files = append(files, 
			filepath.Join(path, "templates", "index", "search_form.tmpl"))
	return template.Must(template.ParseFiles(files...))
}

func newPksIndexTemplate(path string) *template.Template {
	files, _ := filepath.Glob(filepath.Join(path, "templates", "*.tmpl"))
	files = append(files, 
			filepath.Join(path, "templates", "pks", "index.tmpl"))
	return template.Must(template.ParseFiles(files...))
}
