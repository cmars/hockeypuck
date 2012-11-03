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
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"launchpad.net/hockeypuck"
)

var hkpServer *string = flag.String("hkp", "localhost:11371", "HKP server hostname:port")
var path *string = flag.String("path", "", "PGP keyrings to be loaded")

func usage() {
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	flag.Parse()
	loadAll(*path, *hkpServer)
}

func loadAll(path string, hkpserver string) (err error) {
	keyfiles, err := filepath.Glob(path)
	if err != nil {
		return err
	}
	var f *os.File
	for i := 0; i < len(keyfiles); i++ {
		keyfile := keyfiles[i]
		f, err = os.Open(keyfile)
		if err != nil {
			log.Println("Failed to open", keyfile, ":", err)
			continue
		} else {
			log.Println("Loading keys from", keyfile)
		}
		armorChan := parse(f)
		for armor := range armorChan {
			log.Println("got key")
			resp, err := http.PostForm(
				fmt.Sprintf("http://%s/pks/add", hkpserver),
						url.Values{"keytext": {string(armor)}})
			if err != nil {
				log.Println("Error posting key:", err)
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
		f.Close()
	}
	return
}

func parse(f io.Reader) (armorChan chan []byte) {
	armorChan = make(chan []byte)
	keyChan, errChan := hockeypuck.ReadKeys(f)
	go func(){
		defer close(armorChan)
		for {
			select {
			case key, moreKeys :=<-keyChan:
				if !moreKeys {
					return
				}
				out := bytes.NewBuffer([]byte{})
				err := hockeypuck.WriteKey(out, key)
				if err == nil {
					armorChan <- out.Bytes()
				} else {
					log.Println("Error writing key:", err)
				}
			case err, hasErr :=<-errChan:
				if err != nil {
					log.Println("Error loading key:", err)
				}
				if !hasErr {
					return
				}
			}
		}
	}()
	return armorChan
}
