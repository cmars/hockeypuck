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
	"bytes"
	"flag"
	"fmt"
	"github.com/pelletier/go-toml"
	"io"
	"log"
	"strconv"
)

var config *Settings

func Config() *Settings {
	return config
}

type Settings struct {
	*toml.TomlTree
}

func (s *Settings) GetString(key string) string {
	if s, is := s.Get(key).(string); is {
		return s
	}
	return ""
}

func (s *Settings) GetInt(key string) int {
	switch v := s.Get(key).(type) {
	case int:
		return v
	case int64:
		return int(v)
	default:
		i, err := strconv.Atoi(fmt.Sprintf("%v", v))
		if err != nil {
			panic(err)
		}
		s.Set(key, i)
		return i
	}
}

func (s *Settings) GetBool(key string) bool {
	var result bool
	switch v := s.Get(key).(type) {
	case bool:
		return v
	case int:
		result = v != 0
	case string:
		b, err := strconv.ParseBool(v)
		result = err == nil && b
	default:
		result = false
	}
	s.Set(key, result)
	return result
}

func LoadConfig(r io.Reader) (err error) {
	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, r)
	if err != nil {
		return
	}
	var tree *toml.TomlTree
	if tree, err = toml.Load(buf.String()); err != nil {
		return
	}
	config = &Settings{tree}
	config.loadFlagOverrides()
	return
}

func LoadConfigFile(path string) (err error) {
	var tree *toml.TomlTree
	if tree, err = toml.LoadFile(path); err != nil {
		return
	}
	config = &Settings{tree}
	config.loadFlagOverrides()
	return
}

func (config *Settings) loadFlagOverrides() {
	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		if config.Get(f.Name) == nil {
			config.Set(f.Name, f.Value.String())
		} else if f.Value.String() != f.DefValue {
			log.Println("Warning: Config file taking precedence over command-line flag:", f.Name)
		}
	})
}
