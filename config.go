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
package hockeypuck

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

func LogCfg() {
	flag.VisitAll(func(f *flag.Flag) {
		log.Println(f.Name, "=", f.Value)
	})
}

func ParseCfg() {
	var err error
	var f *os.File
	var bf *bufio.Reader
	var mkline *bytes.Buffer
	var fi os.FileInfo
	if fi, err = os.Stat(CONFIG_PATH); err != nil || fi.IsDir() {
		// no config file or not found
		goto CFGERR
	}
	f, err = os.Open(CONFIG_PATH)
	if err != nil {
		goto CFGERR
	}
	fmt.Fprintf(os.Stderr, "Reading configuration from %v\n", f.Name())
	bf = bufio.NewReader(f)
	mkline = bytes.NewBuffer([]byte{})
	for {
		part, prefix, err := bf.ReadLine()
		if err != nil {
			break
		}
		mkline.Write(part)
		if !prefix {
			err = ParseCfgLine(string(mkline.Bytes()))
			if err != nil {
				panic(fmt.Sprintf(
					"Error in configuration file %v: %v\n",
					CONFIG_PATH, err))
			}
			mkline.Reset()
		}
	}
	return
CFGERR:
	fmt.Fprintf(os.Stderr, "%v\n", err)
	return
}

func ParseCfgLine(line string) (err error) {
	line = strings.TrimSpace(line)
	if line[0] == '#' {
		return
	}
	parts := strings.Split(line, "=")
	if len(parts) != 2 {
		return errors.New(fmt.Sprintf(
			"Expected line of form 'key = value', got: %v", line))
	}
	key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	flag.Set(key, value)
	return
}
