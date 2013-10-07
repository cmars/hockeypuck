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
	"fmt"
	ht "html/template"
	"launchpad.net/hockeypuck/hkp"
	"net/http"
	"strings"
	tt "text/template"
	"time"
)

const indexPageTmplSrc = `{{/*

*/}}{{ define "PageHeader" }}{{/*
*/}}<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd" >
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Search results for '{{ .Lookup.Search }}'</title>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
<style type="text/css">
/*<![CDATA[*/
 .uid { color: green; text-decoration: underline; }
 .warn { color: red; font-weight: bold; }
/*]]>*/
</style></head><body><h1>Search results for '{{ .Lookup.Search }}'</h1>{{ end }}{{/*

*/}}{{ define "PageFooter" }}</body></html>{{ end }}{{/*

*/}}{{ define "IndexColHeader" }}<pre>Type bits/keyID     Date       User ID
</pre>{{ end }}{{/*

*/}}{{ define "IndexPubkey" }}<hr /><pre>{{ $fp := .Fingerprint }}
pub  {{ .BitLen }}{{ .Algorithm | algocode }}/<a href="/pks/lookup?op=get&amp;search=0x{{ .Fingerprint }}">{{ .ShortId | upper }}</a> {{ .Creation | date }} {{/*
*/}}{{ range $i, $uid := .UserIds }}{{/*
*/}}{{ if $i }}                               {{ $uid.Keywords }}{{/*
*/}}{{ else }}<a href="/pks/lookup?op=vindex&amp;fingerprint=on&amp;search=0x{{ $fp }}">{{ $uid.Keywords }}</a>{{ end }}
{{ end }}{{ end }}{{/*

*/}}{{ define "IndexPage" }}{{ template "PageHeader" . }}{{ $lookup := .Lookup }}{{/*
*/}}{{ template "IndexColHeader" }}{{/*
*/}}{{ range $i, $key := .Keys }}{{ template "IndexPubkey" $key }}{{/*
*/}}{{ if $lookup.Fingerprint }}{{/*
*/}}	 Fingerprint={{ $key.Fingerprint | fpformat | upper }}{{ end }}{{/*
*/}}</pre>{{ end }}{{/*
*/}}{{ template "PageFooter" }}{{ end }}{{/*

*/}}{{ define "VindexColHeader" }}<pre>Type bits/keyID     cr. time   exp time   key expir
</pre>{{ end }}{{/*

*/}}{{ define "VindexPage" }}{{ template "PageHeader" . }}{{ $lookup := .Lookup }}{{/*
*/}}{{ template "VindexColHeader" . }}{{/*
*/}}{{ range $i, $key := .Keys }}<hr /><pre><strong>pub</strong>  {{ .BitLen }}{{ .Algorithm | algocode }}/<a href="/pks/lookup?op=get&amp;search=0x{{ .Fingerprint }}">{{ .ShortId | upper }}</a> {{ .Creation | date }}{{/*
*/}}{{ if $lookup.Fingerprint }}
	 Fingerprint={{ $key.Fingerprint | fpformat | upper }}{{ end }}{{/*
*/}}{{ range $i, $uid := $key.UserIds }}

<strong>uid</strong> <span class="uid">{{ $uid.Keywords }}</span>{{/*
*/}}{{ range $i, $sig := $uid.Signatures }}
sig <span {{ if $sig|sigWarn }}class='warn'{{ end }}>{{ $sig|sigLabel }}</span>  <a href="/pks/lookup?op=get&amp;search=0x{{ $sig.IssuerKeyId|upper }}">{{ $sig.IssuerShortId|upper }}</a> {{ $sig.Creation|date }} {{ if equal ($key.KeyId) ($sig.IssuerKeyId) }}__________ {{ $sig.Expiration|date|blank }} [selfsig]{{ else }}{{ $sig.Expiration|date|blank }} __________ {{ $sig.IssuerShortId|upper }}{{ end }}{{ end }}{{/*
*/}}{{ end }}{{/* range $key.UserIds
*/}}{{ range $i, $subkey := $key.Subkeys }}

<strong>sub</strong>  {{ .BitLen }}{{ .Algorithm | algocode }}/{{ .ShortId | upper }} {{ .Creation | date }}{{ range $i, $sig := $subkey.Signatures }}
sig <span {{ if $sig|sigWarn }}class='warn'{{ end }}>{{ $sig|sigLabel }}</span>  <a href="/pks/lookup?op=get&amp;search=0x{{ $sig.IssuerKeyId|upper }}">{{ $sig.IssuerShortId|upper }}</a> {{ $sig.Creation|date }} {{ if equal ($key.KeyId) ($sig.IssuerKeyId) }}__________ {{ $sig.Expiration|date|blank }} []{{ else }}{{ $sig.Expiration|date|blank }} __________ {{ $sig.IssuerShortId|upper }}{{ end }}{{ end }}{{/*
*/}}{{ end }}{{/* range .$key.Subkeys
*/}}{{ end }}{{/* range .Keys
*/}}{{ template "PageFooter" }}{{ end }}{{/*
*/}}{{ if .Verbose }}{{ template "VindexPage" . }}{{ else }}{{ template "IndexPage" . }}{{ end }}`

var indexPageTmpl *ht.Template

const indexMrTmplSrc = `{{ define "IndexMr" }}{{/*
*/}}info:1:1{{/*
*/}}{{ $lookup := .Lookup }}{{ range $keyi, $key := .Keys }}
pub:{{ if $lookup.Fingerprint }}{{ $key.Fingerprint|upper }}{{ else }}{{ $key.ShortId|upper }}{{ end }}:{{ $key.Algorithm }}:{{ $key.BitLen }}:{{ $key.Creation.Unix }}:{{ $key.Expiration|expunix }}:{{ range $uidi, $uid := $key.UserIds }}
uid:{{ $uid.Keywords|escapeColons }}:{{ (maxSelfSig $key $uid.Signatures).Creation.Unix }}:{{ (maxSelfSig $key $uid.Signatures).Expiration|expunix }}:{{ end }}{{ end }}{{/*
*/}}{{ end }}{{/*

*/}}{{ template "IndexMr" . }}`

var indexMrTmpl *tt.Template

func fingerprintFormat(fp string) string {
	var result []rune
	for i, r := range fp {
		if i > 0 {
			if i%4 == 0 {
				result = append(result, ' ')
			}
			if i%20 == 0 && len(fp) == 40 {
				result = append(result, ' ')
			}
		}
		result = append(result, r)
	}
	return string(result)
}

func escapeColons(s string) string {
	var result []rune
	for _, r := range s {
		if r == ':' {
			result = append(result, []rune(`\x3a`)...)
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

func sigWarn(sig *Signature) bool {
	if time.Now().Unix() > sig.Expiration.Unix() {
		return true
	}
	switch sig.SigType {
	case 0x28:
		return true
	case 0x30:
		return true
	}
	return false
}

func sigLabel(sig *Signature) string {
	sigName := "sig"
	if time.Now().Unix() > sig.Expiration.Unix() {
		sigName = "exp"
	}
	switch sig.SigType {
	case 0x10:
		return fmt.Sprintf(" %s ", sigName)
	case 0x11:
		return fmt.Sprintf(" %s1", sigName)
	case 0x12:
		return fmt.Sprintf(" %s2", sigName)
	case 0x13:
		return fmt.Sprintf(" %s3", sigName)
	case 0x18:
		return "sbind"
	case 0x28:
		return "revok"
	case 0x30:
		return "revok"
	}
	return sigName
}

func init() {
	funcs := map[string]interface{}{
		"algocode":     AlgorithmCode,
		"fpformat":     fingerprintFormat,
		"upper":        strings.ToUpper,
		"maxSelfSig":   maxSelfSig,
		"escapeColons": escapeColons,
		"equal":        func(s, r string) bool { return s == r },
		"sigLabel":     sigLabel,
		"sigWarn":      sigWarn,
		"expunix": func(t time.Time) string {
			if t.Unix() == NeverExpires.Unix() {
				return ""
			}
			return fmt.Sprintf("%d", t.Unix())
		},
		"blank": func(s string) string {
			if s == "" {
				return "__________"
			}
			return s
		},
		"date": func(t time.Time) string {
			if t.Unix() == NeverExpires.Unix() {
				return ""
			}
			return t.Format("2006-01-02")
		}}
	indexPageTmpl = ht.Must(ht.New("indexPage").Funcs(funcs).Parse(indexPageTmplSrc))
	indexMrTmpl = tt.Must(tt.New("indexPage").Funcs(funcs).Parse(indexMrTmplSrc))
}

type IndexResponse struct {
	Lookup  *hkp.Lookup
	Keys    []*Pubkey
	Verbose bool
	Err     error
}

func (r *IndexResponse) Error() error {
	return r.Err
}

func (r *IndexResponse) WriteTo(w http.ResponseWriter) error {
	for _, key := range r.Keys {
		Sort(key)
	}
	if r.Lookup.MachineReadable() {
		w.Header().Add("Content-Type", "text/plain")
		r.Err = indexMrTmpl.Execute(w, r)
	} else {
		w.Header().Add("Content-Type", "text/html")
		r.Err = indexPageTmpl.Execute(w, r)
	}
	return r.Err
}
