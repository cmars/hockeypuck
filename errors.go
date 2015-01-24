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
	"errors"

	"gopkg.in/errgo.v1"
)

func IsNotFound(err error) bool {
	return errgo.Cause(err) == ErrKeyNotFound
}

// Lookup key was not found in the database.
var ErrKeyNotFound = errors.New("key not found.")

// An internal inconsistency between the stored key material and our indexing was detected.
var ErrInconsistentKey = errors.New("stored key is internally inconsistent")

// Key ID is invalid.
var ErrInvalidKeyId = errors.New("invalid key ID")

// Key hash is invalid.
var ErrInvalidKeyHash = errors.New("invalid key hash")

// A lookup with a short key ID found a collision.
// This is quite possible with short key IDs, remotely possibly with long IDs.
var ErrKeyIdCollision = errors.New("key ID matches multiple public keys")

// A query resulted in more responses than we'd care to respond with.
var ErrTooManyResponses = errors.New("too many responses")

// Something was attempted that isn't fully baked yet.
var ErrUnsupportedOperation = errors.New("unsupported operation")

// Template path was not found. Installation or configuration problem.
var ErrTemplatePathNotFound = errors.New("could not locate templates")
