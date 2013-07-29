package hkp

import (
	"launchpad.net/hockeypuck"
)

type Settings struct {
	*hockeypuck.Settings
}

func Config() *Settings {
	return &Settings{hockeypuck.Config()}
}
