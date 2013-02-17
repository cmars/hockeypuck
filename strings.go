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
	"strings"
	"unicode"
	"unicode/utf8"
)

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func isUserDelim(c rune) bool {
	switch c {
	case '<':
		return true
	case '>':
		return true
	case '(':
		return true
	case ')':
		return true
	case '@':
		return true
	}
	return unicode.IsSpace(c)
}

// Split a user ID string into fulltext searchable keywords.
func SplitUserId(id string) []string {
	m := make(map[string]bool)
	for _, s := range strings.FieldsFunc(id, isUserDelim) {
		s = strings.ToLower(strings.TrimFunc(s, isUserDelim))
		if len(s) > 2 {
			m[s] = true
		}
	}
	result := []string{}
	for k, _ := range m {
		result = append(result, CleanUtf8(k))
	}
	return result
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
