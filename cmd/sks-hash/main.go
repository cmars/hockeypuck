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

// sks-hash is a debugging tool that calculates
// a message digest of all information associated
// with a public key using the same method as SKS.
package main

import (
	"fmt"
	"launchpad.net/hockeypuck/openpgp"
	"os"
)

func main() {
	for keyRead := range openpgp.ReadValidKeys(os.Stdin) {
		if keyRead.Pubkey != nil {
			fmt.Println(keyRead.Pubkey.Fingerprint(), keyRead.Pubkey.Md5)
		}
	}
}
