package cli

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// HTTP bind address option
var HttpBind *string = flag.String("http", ":11371", "http bind address")

// Number of workers to spawn
var NumWorkers *int = flag.Int("workers", runtime.NumCPU(), "Number of workers")

// Path to Hockeypuck's installed www directory
var WwwRoot *string = flag.String("www-root",
		"/var/lib/hockeypuck/www",
		"Location of static web server files and templates")

var LogFile *string = flag.String("logfile", "", "Logfile (default stderr)")

func OpenLog() *log.Logger {
	var LogOut io.Writer = os.Stderr
	var logFerr error
	if *LogFile != "" {
		LogOut, logFerr = os.OpenFile(*LogFile, os.O_WRONLY | os.O_APPEND | os.O_CREATE, 0644)
		if logFerr != nil {
			LogOut = os.Stderr
		}
	}
	newLog := log.New(LogOut, fmt.Sprintf("[%s]", filepath.Base(os.Args[0])),
			log.LstdFlags | log.Lshortfile)
	if logFerr != nil {
		newLog.Println("Warning: could not open logfile", LogFile, ":", logFerr)
		newLog.Println("Logging will be sent to stderr")
	}
	return newLog
}
