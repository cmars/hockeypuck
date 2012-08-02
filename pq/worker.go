package pq

import (
	_ "github.com/bmizerany/pq"
	//"database/sql"
	"bytes"
	"crypto/rand"
	"encoding/ascii85"
	"errors"
	"io"
)

const UUID_LEN = 20

func NewUuid() (string, error) {
	buf := bytes.NewBuffer([]byte{})
	enc := ascii85.NewEncoder(buf)
	n, err := io.CopyN(enc, rand.Reader, UUID_LEN)
	if err != nil {
		return "", err
	}
	if n < UUID_LEN {
		return "", errors.New("Failed to generate UUID")
	}
	return string(buf.Bytes()), nil
}
