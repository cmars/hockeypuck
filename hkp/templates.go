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
	"strings"
	"time"
)

const footerTmplSrc = `
{{define "page_footer"}}
<div id="footer">
<div id="copyright"><a href="https://launchpad.net/hockeypuck">Hockeypuck OpenPGP Key Server</a> - Copyright (C) 2012 <a href="/pks/lookup?op=vindex&search=0x44A2D1DB">Casey Marshall</a> and Hockeypuck contributors.</div>
<div id="copyleft">This program is free software: you can redistribute it and/or modify
  it under the terms of the
  <a href="https://www.gnu.org/licenses/agpl-3.0.html">GNU Affero General Public License</a>
  as published by the Free Software Foundation, version 3.</div>
</div>
{{end}}`

const headTmplSrc = `
{{define "head"}}
<link rel="stylesheet" href="/css/reset.css" />
<link rel="stylesheet" href="/css/hkp.css" />
{{end}}`

const headerTmplSrc = `
{{define "page_header"}}
<div id="header">
<h1><a id="logo" href="/">Hockeypuck</a></h1>
<div id="topmenu">
	<ul>
		<li><span class="menu-label">OpenPGP:</span></li>
		<li><a href="/openpgp/lookup">Search</a></li>
		<li><a href="/openpgp/add">Add</a></li>
		<li><a href="/pks/lookup?op=stats">Stats</a></li>
		<li><span class="menu-label">Machines:</span></li>
		<li><span class="todo-link">SSH</span></li>
		<li><span class="todo-link">SSL/TLS</span></li>
		<li class="about"><a href="https://launchpad.net/hockeypuck">Project Home</a></li>
	</ul>
</div>
</div>
{{end}}`

const layoutTmplSrc = `
{{define "top"}}
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>{{template "title"}}</title>
{{template "head"}}
</head>
<body>
<div id="container">
{{template "page_header"}}
<div id="main">
{{end}}

{{define "bottom"}}
</div><!-- main -->
</div><!-- container -->
{{template "page_footer"}}
</body>
</html>
{{end}}

{{define "layout"}}
{{template "top" .}}
{{template "page_content" .}}
{{template "bottom" .}}
{{end}}`

const addFormTmplSrc = `
{{define "title"}}Hockeypuck | Add Public Key{{end}}

{{define "page_content"}}
<h2 class="pks-add">Add Public Key</h2>
<p>Paste the ASCII-armored public key block into the form below.</p>
<form class="pks-add" action="/pks/add" method="post">
	<div>
		<textarea name="keytext" cols="66" rows="20"></textarea>
	</div>
	<div>
		<input id="add_submit" type="submit" value="Add Public Key"></input>
	</div>
</form>
{{end}}`

const addResultTmplSrc = `
{{define "title"}}Hockeypuck | Updated Public Keys{{end}}

{{define "page_content"}}
<h2>Updated Public Keys</h2>
{{range .Changes}}
<p><a href="/pks/lookup?op=index&search=0x{{.Fingerprint}}">{{.}}</a></p>
{{end}}
{{end}}`

const searchFormTmplSrc = `
{{define "title"}}Hockeypuck | Search OpenPGP Public Keys{{end}}

{{define "page_content"}}
<h2 class="pks-search">OpenPGP Search</h2>
<form class="pks-search" method="post">
	<div>
		<input name="search" type="search"></input>
	</div>
	<div>
		<input id="search_submit" formaction="/pks/lookup?op=index" type="submit" value="Public Key Search"></input>
		<input id="get_submit" formaction="/pks/lookup?op=get" type="submit" value="I'm Feeling Lucky"></input>
	</div>
</form>
{{end}}`

const statsTmplSrc = `
{{define "title"}}Hockeypuck | Server Status{{end}}

{{define "page_content"}}
<h2>Server Status</h2>
<table>
<tr><th>Hostname:</th><td>{{.Hostname}}</td></tr>
<tr><th>Port:</th><td>{{.Port}}</td></tr>
<tr><th>Version:</th><td>{{.Version}}</td></tr>
</table>
{{if .PksPeers}}
<h2>Outgoing Mailsync Peers</h2>
<table>
<tr><th>Email Address</th><th>Last Synchronized</th></tr>
{{range .PksPeers}}
<tr><td>{{.Addr}}</td><td>{{timef .LastSync}}</td></tr>
{{end}}
</table>
{{end}}
<h2>Statistics</h2>
<table>
<tr><th>Total number of keys:</th><td>{{.TotalKeys}}</td></tr>
</table>
{{if .KeyStatsHourly}}
<h3>Keys loaded in the last 24 hours</h3>
<table>
<tr><th>Hour</th><th>New</th><th>Updated</th></tr>
{{range .KeyStatsHourly}}
<tr><td>{{.Hour}}</td><td>{{.Created}}</td><td>{{.Modified}}</td></tr>
{{end}}
</table>
{{end}}
{{if .KeyStatsDaily}}
<h3>Keys loaded in the last 7 days</h3>
<table>
<tr><th>Day</th><th>New</th><th>Updated</th></tr>
{{range .KeyStatsDaily}}
<tr><td>{{.Day}}</td><td>{{.Created}}</td><td>{{.Modified}}</td></tr>
{{end}}
</table>
{{end}}
{{end}}`

// baseTmplSrcs contains common templates that need to be defined
// for all Hockeypuck HKP templates.
var BaseTemplateSrcs = []string{
	headTmplSrc, headerTmplSrc, footerTmplSrc,
	layoutTmplSrc}

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

func mustParseHkpTemplate(src string) *template.Template {
	return template.Must(template.New("placeholder").Parse(strings.Join(
		append(BaseTemplateSrcs, src), "")))
}

func init() {
	SearchFormTemplate = mustParseHkpTemplate(searchFormTmplSrc)
	AddFormTemplate = mustParseHkpTemplate(addFormTmplSrc)
	AddResultTemplate = mustParseHkpTemplate(addResultTmplSrc)
	StatsTemplate = template.Must(template.New("placeholder").Funcs(
		template.FuncMap{"timef": func(ts int64) string {
			tm := time.Unix(0, ts)
			return tm.Format(time.RFC3339)
		}}).Parse(strings.Join(append(BaseTemplateSrcs, statsTmplSrc), "")))
}
