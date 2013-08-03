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
	return s.GetStringDefault(key, "")
}

func (s *Settings) GetStringDefault(key string, defaultValue string) string {
	if s, is := s.Get(key).(string); is {
		return s
	}
	return defaultValue
}

func (s *Settings) MustGetInt(key string) int {
	if v, err := s.getInt(key); err == nil {
		return v
	} else {
		panic(err)
	}
}

func (s *Settings) GetIntDefault(key string, defaultValue int) int {
	if v, err := s.getInt(key); err == nil {
		return v
	} else {
		return defaultValue
	}
}

func (s *Settings) getInt(key string) (int, error) {
	switch v := s.Get(key).(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	default:
		if i, err := strconv.Atoi(fmt.Sprintf("%v", v)); err != nil {
			return 0, err
		} else {
			s.Set(key, i)
			return i, nil
		}
	}
	panic("unreachable")
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

func (s *Settings) GetStrings(key string) (value []string) {
	if strs, is := s.Get(key).([]interface{}); is {
		for _, v := range strs {
			if str, is := v.(string); is {
				value = append(value, str)
			}
		}
	}
	return
}

func SetConfig(contents string) (err error) {
	var tree *toml.TomlTree
	if tree, err = toml.Load(contents); err != nil {
		return
	}
	config = &Settings{tree}
	return
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
			config.Set("hockeypuck."+f.Name, f.Value.String())
		} else if f.Value.String() != f.DefValue {
			log.Println("Warning: Config file taking precedence over command-line flag:", f.Name)
		}
	})
}
