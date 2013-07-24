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
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const CONFIG_PATH = "/etc/hockeypuck/hockeypuck.conf"

// Logfile option
func init() { flag.String("logfile", "", "Logfile (default stderr)") }
func (s *Settings) LogFile() string {
	return s.GetString("logfile")
}

var logOut io.Writer = nil

func InitLog() {
	if Config().LogFile() != "" {
		// Handle signals for log rotation
		sigChan := make(chan os.Signal)
		signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
		go func() {
			for {
				select {
				case _ = <-sigChan:
					closeable, canClose := logOut.(io.WriteCloser)
					openLog()
					if canClose {
						closeable.Close()
					}
					log.Println("Reopened logfile")
				}
			}
		}()
	}
	// Open the log
	openLog()
}

func openLog() {
	if Config().LogFile() != "" {
		var err error
		logOut, err = os.OpenFile(Config().LogFile(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			logOut = os.Stderr
		}
		log.SetOutput(logOut)
		if err != nil {
			log.Println("Failed to open logfile", err)
		}
	} else {
		log.SetOutput(os.Stderr)
	}
	log.SetPrefix(filepath.Base(os.Args[0]))
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
