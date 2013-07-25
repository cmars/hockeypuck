package openpgp

import (
	"launchpad.net/hockeypuck"
)

type OpenpgpSettings struct {
	*hockeypuck.Settings
}

func OpenpgpConfig() *OpenpgpSettings {
	return &OpenpgpSettings{hockeypuck.Config()}
}
