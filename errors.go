package hockeypuck

import (
	"errors"
)

// Lookup key was not found in the database.
var KeyNotFound = errors.New("Key not found.")

// An internal inconsistency between the stored key material and our indexing was detected.
var InternalKeyInvalid = errors.New("Stored key ring is invalid.")

// Key ID is invalid.
var InvalidKeyId = errors.New("Invalid key ID.")

// A lookup with a short key ID found a collision.
// This is quite possible with short key IDs, remotely possibly with long IDs.
var KeyIdCollision = errors.New("Short key ID matches multiple public keys. Try again with a longer key ID.")

// A query resulted in more responses than we'd care to respond with.
var TooManyResponses = errors.New("Too many responses.")

// Something was attempted that isn't fully baked yet.
var UnsupportedOperation = errors.New("Unsupported operation.")
