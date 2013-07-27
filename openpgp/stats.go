package openpgp

import (
	"launchpad.net/hockeypuck/hkp"
)

func (w *Worker) Stats(l *hkp.Lookup) {
	l.Response() <- &NotImplementedResponse{}
}
