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

package noimp

import (
	"errors"
	_ "fmt"
	"launchpad.net/hockeypuck"
	"net/http"
	_ "os"
)

type NoimpWorker struct {
	Hkp        *hockeypuck.HkpServer
	exitLookup chan bool
	exitAdd    chan bool
}

func NewWorker(hkp *hockeypuck.HkpServer) *NoimpWorker {
	noimp := &NoimpWorker{
		Hkp:        hkp,
		exitLookup: make(chan bool),
		exitAdd:    make(chan bool)}
	noimp.start()
	return noimp
}

type errorist struct {
}

func (e *errorist) Error() error {
	return errors.New("Not implemented")
}

func (e *errorist) WriteTo(_ http.ResponseWriter) error {
	return e.Error()
}

func (w *NoimpWorker) start() {
	go func() {
		for shouldRun := true; shouldRun; {
			select {
			case lookup := <-w.Hkp.LookupRequests:
				//fmt.Fprintf(os.Stderr, "lookup\n")
				lookup.Response() <- &errorist{}
			case _ = <-w.exitLookup:
				shouldRun = false
			}
		}
	}()
	go func() {
		for shouldRun := true; shouldRun; {
			select {
			case add := <-w.Hkp.AddRequests:
				//fmt.Fprintf(os.Stderr, "add\n")
				add.Response() <- &errorist{}
			case _ = <-w.exitAdd:
				shouldRun = false
			}
		}
	}()
}

func (w *NoimpWorker) Stop() {
	w.exitLookup <- true
	w.exitAdd <- true
}
