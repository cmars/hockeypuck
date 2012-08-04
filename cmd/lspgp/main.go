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

package main

import (
	"fmt"
	"os"
	"bitbucket.org/cmars/go.crypto/openpgp"
	// importing these hash algorithms ensures they are registered at runtime
	_ "bitbucket.org/cmars/go.crypto/md4"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	_ "bitbucket.org/cmars/go.crypto/ripemd160"
)

func die(err error, format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Fprintf(os.Stderr, ": %s\n", err.Error())
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <pubring file>\n", os.Args[0])
		os.Exit(1)
	}
	keyringFile:= os.Args[1]
	keyringReader, err := os.Open(keyringFile)
	if err != nil {
		die(err, "Error opening %s", keyringFile)
	}
	defer keyringReader.Close()
	keyring, err := openpgp.ReadKeyRing(keyringReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading keyring: %v", err)
	}
	for _, key := range keyring {
		fmt.Printf("key: %d\n", key.PrimaryKey.KeyId)
	}
}
