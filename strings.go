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
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MIN_KEYWORD_LEN = 3

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

var UserIdRegex *regexp.Regexp = regexp.MustCompile(`^\s*(\S.*\b)?\s*(\([^(]+\))?\s*(<[^>]+>)?$`)

func isUserDelim(c rune) bool {
	return !unicode.IsLetter(c) && !unicode.IsDigit(c)
}

// Split a user ID string into fulltext searchable keywords.
func SplitUserId(id string) (keywords []string) {
	matches := UserIdRegex.FindStringSubmatch(id)
	if len(matches) > 1 {
		match := keywordNormalize(matches[1])
		if len(match) >= MIN_KEYWORD_LEN {
			keywords = append(keywords, match)
		}
	}
	if len(matches) > 2 {
		match := keywordNormalize(strings.Trim(matches[2], "()"))
		if len(match) >= MIN_KEYWORD_LEN {
			keywords = append(keywords, match)
		}
	}
	if len(matches) > 3 {
		match := strings.ToLower(strings.Trim(matches[3], "<>"))
		if len(match) >= MIN_KEYWORD_LEN {
			keywords = append(keywords, match)
		}
	}
	return keywords
}

func keywordNormalize(s string) string {
	var fields []string
	for _, s := range strings.FieldsFunc(s, isUserDelim) {
		s = strings.ToLower(strings.TrimFunc(s, isUserDelim))
		if len(s) > 2 {
			fields = append(fields, s)
		}
	}
	return strings.Join(fields, " ")
}

func CleanUtf8(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		if r == utf8.RuneError {
			runes[i] = '?'
		}
	}
	return string(runes)
}
