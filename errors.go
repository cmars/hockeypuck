package hockeypuck

import (
	"errors"
)

var KeyNotFound = errors.New("Key not found")
var InternalKeyInvalid = errors.New("Stored key armor is invalid")
