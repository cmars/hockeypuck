package hockeypuck

import (
	"io/ioutil"
	"os"
	"strings"
)

const VERSION_PATH = "/etc/hockeypuck/version"

var Version string = "DEVELOPMENT"

func init() {
	if f, err := os.Open(VERSION_PATH); err == nil {
		version, err := ioutil.ReadAll(f)
		if err == nil && len(version) > 0 {
			Version = strings.TrimSpace(string(version))
		}
	}
}
