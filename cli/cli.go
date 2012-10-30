package cli

import (
	"flag"
	"runtime"
)

// HTTP bind address option
var HttpBind *string = flag.String("http", ":11371", "http bind address")

// Number of workers to spawn
var NumWorkers *int = flag.Int("workers", runtime.NumCPU(), "number of workers")

// Path to Hockeypuck's installed www directory
var WwwRoot *string = flag.String("www-root",
		"/var/lib/hockeypuck/www",
		"Location of static web server files and templates")
