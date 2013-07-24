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
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"launchpad.net/hockeypuck"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const ADD_CMD = "add"
const INCREMENTAL_CMD = "incremental"

var hkpServer *string = flag.String("hkp", "localhost:11371", "HKP server hostname:port")
var path *string = flag.String("path", "", "PGP keyrings to be loaded")
var mailAdd *bool = flag.Bool("mail-add", false, "Load key(s) from mailsync message on stdin")

func usage() {
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	flag.Parse()
	hockeypuck.InitLog()
	var err error
	if *mailAdd {
		err = loadMail(*hkpServer)
	} else if *path != "" {
		err = loadAll(*path, *hkpServer)
	} else {
		usage()
	}
	if err != nil {
		log.Println("Error:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func loadMail(hkpserver string) (err error) {
	var msg *mail.Message
	msg, err = mail.ReadMessage(os.Stdin)
	if err != nil {
		return
	}
	subjectValue, has := msg.Header["Subject"]
	if !has || len(subjectValue) == 0 {
		return errors.New("Missing 'Subject:' header")
	}
	subject := strings.ToLower(subjectValue[0])
	bodyBuf := bytes.NewBuffer([]byte{})
	_, err = io.Copy(bodyBuf, msg.Body)
	if err != nil {
		return
	}
	if subject == INCREMENTAL_CMD || subject == ADD_CMD {
		err = loadArmor(hkpserver, string(bodyBuf.Bytes()))
	}
	return
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
			loadArmor(hkpserver, string(armor))
		}
		f.Close()
	}
	return
}

func loadArmor(hkpserver string, armor string) (err error) {
	var resp *http.Response
	resp, err = http.PostForm(
		fmt.Sprintf("http://%s/pks/add", hkpserver),
		url.Values{"keytext": {string(armor)}})
	if err != nil {
		log.Println("Error posting key:", err)
	}
	if resp != nil {
		resp.Body.Close()
	}
	return
}

func parse(f io.Reader) (armorChan chan []byte) {
	armorChan = make(chan []byte)
	keyChan, errChan := hockeypuck.ReadKeys(f)
	go func() {
		defer close(armorChan)
		for {
			select {
			case key, moreKeys := <-keyChan:
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
			case err, hasErr := <-errChan:
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
