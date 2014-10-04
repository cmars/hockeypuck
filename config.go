/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

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

// Package hockeypuck provides common configuration, logging and
// static content for the keyserver.
package hockeypuck

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/pelletier/go-toml"
)

var config *Settings

// Config returns the global Settings for an application built with Hockeypuck.
func Config() *Settings {
	return config
}

// Settings stores configuration options for Hockeypuck.
type Settings struct {
	*toml.TomlTree
}

// GetString returns the string value for the configuration key if set,
// otherwise the empty string.
func (s *Settings) GetString(key string) string {
	return s.GetStringDefault(key, "")
}

// GetStringDefault returns the string value for the configuration key if set,
// otherwise the default value.
func (s *Settings) GetStringDefault(key string, defaultValue string) string {
	if s, is := s.Get(key).(string); is {
		return s
	}
	return defaultValue
}

// MustGetInt returns the int value for the configuration key if set and valid,
// otherwise panics.
func (s *Settings) MustGetInt(key string) int {
	if v, err := s.getInt(key); err == nil {
		return v
	} else {
		panic(err)
	}
}

// GetIntDefault returns the int value for the configuration key if set and valid,
// otherwise the default value.
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
}

// GetBool returns the boolean value for the configuration key if set,
// otherwise false.
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

// GetStrings returns a []string slice for the configuration key if set,
// otherwise an empty slice.
func (s *Settings) GetStrings(key string) []string {
	var value []string
	if strs, is := s.Get(key).([]interface{}); is {
		for _, v := range strs {
			if str, is := v.(string); is {
				value = append(value, str)
			}
		}
	}
	return value
}

// SetConfig sets the global configuration to the TOML-formatted string contents.
func SetConfig(contents string) error {
	tree, err := toml.Load(contents)
	if err != nil {
		return err
	}
	config = &Settings{tree}
	return nil
}

// LoadConfig sets the global configuration to the TOML-formatted reader contents.
func LoadConfig(r io.Reader) error {
	buf := bytes.NewBuffer(nil)
	_, err := io.Copy(buf, r)
	if err != nil {
		return err
	}
	tree, err := toml.Load(buf.String())
	if err != nil {
		return err
	}
	config = &Settings{tree}
	return nil
}

// LoadConfigFile sets the global configuration to the contents from the TOML file path.
func LoadConfigFile(path string) (err error) {
	tree, err := toml.LoadFile(path)
	if err != nil {
		return err
	}
	config = &Settings{tree}
	return nil
}
