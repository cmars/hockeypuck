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

package hockeypuck

import (
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "gopkg.in/hockeypuck/logrus.v0"
)

var logOut io.Writer = nil

// InitLog initializes the logging output to the globally configured settings.
// It also registers SIGHUP, SIGUSR1 and SIGUSR2 to close and reopen the log file
// for logrotate(8) support.
func InitLog(s *Settings) {
	// Handle signals for log rotation
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for {
			select {
			case _ = <-sigChan:
				closeable, ok := logOut.(io.WriteCloser)
				openLog(s)
				if ok {
					closeable.Close()
				}
				log.Info("reopened logfile")
			}
		}
	}()

	// Open the log
	openLog(s)
}

func openLog(s *Settings) {
	defer func() {
		level, err := log.ParseLevel(strings.ToLower(s.LogLevel))
		if err != nil {
			log.Warningf("invalid LogLevel %q: %v", s.LogLevel, err)
			return
		}
		log.SetLevel(level)
	}()

	if s.LogFile == "" {
		logOut = nil
		log.SetOutput(os.Stderr)
		return
	}

	var err error
	logOut, err = os.OpenFile(s.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Errorf("failed to open LogFile: %v", err)
		return
	}
	log.SetOutput(logOut)
	log.Debug("log opened")
}
