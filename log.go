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
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

const CONFIG_PATH = "/etc/hockeypuck/hockeypuck.conf"

// Logfile option
var LogFile *string = flag.String("logfile", "", "Logfile (default stderr)")

var logOut *log.Logger = nil

func EnsureLog(logp **log.Logger) {
	if *logp == nil {
		if logOut == nil {
			logOut = OpenLog()
		}
		*logp = logOut
	}
}

func OpenLog() *log.Logger {
	var LogOut io.Writer = os.Stderr
	var logFerr error
	if *LogFile != "" {
		LogOut, logFerr = os.OpenFile(*LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if logFerr != nil {
			LogOut = os.Stderr
		}
	}
	newLog := log.New(LogOut, fmt.Sprintf("[%s]", filepath.Base(os.Args[0])),
		log.LstdFlags|log.Lshortfile)
	if logFerr != nil {
		newLog.Println("Warning: could not open logfile", LogFile, ":", logFerr)
		newLog.Println("Logging will be sent to stderr")
	}
	return newLog
}
