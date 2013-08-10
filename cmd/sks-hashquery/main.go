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

// sks-hashquery is a debugging tool that tests the /pks/hashquery
// bulk key download used by SKS.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/cmars/conflux/recon"
	"io/ioutil"
	"launchpad.net/hockeypuck/openpgp"
	"log"
	"net/http"
	"os"
)

func die(args ...interface{}) {
	log.Println(args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 {
		die("Usage: host:port hash1[,hash2,...,hashn]")
	}
	postData := bytes.NewBuffer(nil)
	recon.WriteInt(postData, len(os.Args)-2)
	for _, arg := range os.Args[2:] {
		digestBytes, err := hex.DecodeString(arg)
		if err != nil {
			die(err)
		}
		err = recon.WriteInt(postData, len(digestBytes))
		if err != nil {
			die(err)
		}
		_, err = postData.Write(digestBytes)
		if err != nil {
			die(err)
		}
	}
	resp, err := http.Post(fmt.Sprintf("http://%s/pks/hashquery", os.Args[1]),
		"sks/hashquery", bytes.NewReader(postData.Bytes()))
	if err != nil {
		die(err)
	}
	respContents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		die(err)
	}
	respBuf := bytes.NewBuffer(respContents)
	nkeys, err := recon.ReadInt(respBuf)
	if err != nil {
		die(err)
	}
	log.Println("Response from server:", nkeys, " keys found")
	for i := 0; i < nkeys; i++ {
		keyLen, err := recon.ReadInt(respBuf)
		if err != nil {
			die(err)
		}
		log.Println("Key#", i+1, ":", keyLen, "bytes")
		keyData := make([]byte, keyLen)
		_, err = respBuf.Read(keyData)
		if err != nil {
			die(err)
		}
		printKey(keyData)
	}
	log.Println("Remaining response:", respBuf.Len(), "bytes")
	fmt.Printf("%x", respBuf.Bytes())
}

func printKey(keyData []byte) {
	for readKey := range openpgp.ReadValidKeys(bytes.NewBuffer(keyData)) {
		log.Println(readKey)
	}
}
