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
	"crypto/rand"
	"github.com/bmizerany/assert"
	"testing"
)

func TestUserIdRegex(t *testing.T) {
	// Name, comment, email address
	matches := UserIdRegex.FindStringSubmatch("Alice Practice (Crystal Castles) <alice.practice@example.com>")
	assert.Equal(t, matches[1], "Alice Practice")
	assert.Equal(t, matches[4], "Crystal Castles")
	assert.Equal(t, matches[6], "alice.practice@example.com")
	// Name only
	matches = UserIdRegex.FindStringSubmatch("John E. Smoke")
	assert.Equal(t, matches[1], "John E. Smoke")
	// Name and comment
	matches = UserIdRegex.FindStringSubmatch("John E. Smoke (John W. Smoke)")
	assert.Equal(t, matches[1], "John E. Smoke")
	assert.Equal(t, matches[4], "John W. Smoke")
	// Name and email address
	matches = UserIdRegex.FindStringSubmatch("John E. Smoke <theflameitself@example.com>")
	assert.Equal(t, matches[1], "John E. Smoke")
	assert.Equal(t, matches[6], "theflameitself@example.com")
	// Email address only
	matches = UserIdRegex.FindStringSubmatch("<noname@example.com>")
	assert.Equal(t, matches[6], "noname@example.com")
	// Without angle brackets, could be a name
	matches = UserIdRegex.FindStringSubmatch("noname@example.com")
	assert.Equal(t, matches[1], "noname@example.com")
	// Wat.
	buf := make([]byte, 64)
	for i := 0; i < 10; i++ {
		_, err := rand.Reader.Read(buf)
		assert.Equal(t, err, nil)
		UserIdRegex.FindStringSubmatch(string(buf))
	}
}

func TestSplitUserId(t *testing.T) {
	keywords := SplitUserId("Alice Practice (Crystal Castles) <alice.practice@example.com>")
	assert.Equal(t, "alice practice", keywords[0])
	assert.Equal(t, "alice.practice@example.com", keywords[1])
	// drop short words
	keywords = SplitUserId("John W. Smoke <JOHNNYSMOKE@example.com>")
	assert.Equal(t, "john smoke", keywords[0])
	// lowercase email addresses too
	assert.Equal(t, "johnnysmoke@example.com", keywords[1])
	// search queries
	keywords = SplitUserId("john smoke")
	assert.Equal(t, "john smoke", keywords[0])
	keywords = SplitUserId("johnwsmoke@example.com")
	assert.Equal(t, "johnwsmoke@example.com", keywords[0])
}
