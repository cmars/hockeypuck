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
	"github.com/pelletier/go-toml"
	"log"
	"os"
	"strings"
)

var config *TomlTree

func LoadConfig(r io.Reader) (err error) {
	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, r)
	if err != nil {
		return
	}
	if config, err = toml.Load(buf.String()); err != nil {
		return
	}
	loadFlagOverrides()
	return
}

func LoadConfigFile(path string) (err error) {
	if config, err = toml.LoadFile(path); err != nil {
		return
	}
	loadFlagOverrides()
	return
}

func loadFlagOverrides() {
	flag.VisitAll(func(f *flag.Flag) {
		config.Set(f.Name, f.Value)
	})
}

func Config() map[string]interface{} {
	return config
}
