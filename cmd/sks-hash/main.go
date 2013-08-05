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
package main

import (
	"fmt"
	"launchpad.net/hockeypuck"
	"os"
)

func main() {
	keys, errors := hockeypuck.ReadValidKeys(os.Stdin)
LOOP:
	for {
		select {
		case key, ok := <-keys:
			if key != nil {
				digest := hockeypuck.SksDigest(key)
				fmt.Println(digest)
			}
			if !ok {
				break LOOP
			}
		case err, ok := <-errors:
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
			}
			if !ok {
				break LOOP
			}
		}
	}
}
