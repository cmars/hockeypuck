package hockeypuck

import (
	"errors"
)

var KeyNotFound = errors.New("Key not found.")
var InternalKeyInvalid = errors.New("Stored key ring is invalid.")
var InvalidKeyId = errors.New("Invalid key ID.")
var KeyIdCollision = errors.New("Short key ID matches multiple public keys. Try again with a longer key ID.")
