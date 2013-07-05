package main

import (
	"launchpad.net/hockeypuck"
	"fmt"
	"os"
)

func main() {
	keys, errors := hockeypuck.ReadValidKeys(os.Stdin)
LOOP:
	for {
		select {
		case key, ok :=<-keys:
			if key != nil {
				digest := hockeypuck.SksDigest(key)
				fmt.Println(digest)
			}
			if !ok {
				break LOOP
			}
		case err, ok :=<-errors:
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
			}
			if !ok {
				break LOOP
			}
		}
	}
}
