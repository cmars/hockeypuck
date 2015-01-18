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

// hockeypuck is an OpenPGP keyserver.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"

	"gopkg.in/errgo.v1"
	"launchpad.net/gnuflag"

	. "github.com/hockeypuck/hockeypuck"
	"github.com/hockeypuck/hockeypuck/settings"
)

type usageError struct {
	cmd cmdHandler
	msg string
}

func newUsageError(c cmdHandler, msg string) error {
	return &usageError{cmd: c, msg: msg}
}

func (err *usageError) Error() string {
	return err.msg
}

func (err *usageError) usage() {
	fmt.Fprintln(os.Stderr, err.msg)
	// TODO: format this properly wrt variable width strings
	fmt.Fprintf(os.Stderr, "\n  %s %s\t\t%s\n\n",
		filepath.Base(os.Args[0]), err.cmd.Name(), err.cmd.Desc())
	if err.cmd.Flags() != nil {
		err.cmd.Flags().PrintDefaults()
	}
	os.Exit(1)
}

func die(err error) {
	usageErr, ok := err.(*usageError)
	if ok {
		usageErr.usage()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

type cmdHandler interface {
	Name() string
	Desc() string
	Flags() *gnuflag.FlagSet
	Main() error
}

type subCmd struct {
	flags *gnuflag.FlagSet
}

func (c *subCmd) Flags() *gnuflag.FlagSet { return c.flags }

var cmds []cmdHandler = []cmdHandler{
	newRunCmd(),
	newDeleteCmd(),
	newLoadCmd(),
	newRecoverCmd(),
	newDbCmd(),
	newPbuildCmd(),
	newHelpCmd(),
	newVersionCmd()}

func main() {
	if len(os.Args) < 2 {
		newHelpCmd().Main()
		return
	}
	var cmdArgs []string
	if len(os.Args) > 2 {
		cmdArgs = os.Args[2:]
	}
	var cpuProf bool
	var memProf bool
	for _, cmd := range cmds {
		if cmd.Name() == os.Args[1] {
			if flags := cmd.Flags(); flags != nil {
				flags.BoolVar(&cpuProf, "cpuprof", false, "Enable CPU profiling")
				flags.BoolVar(&memProf, "memprof", false, "Enable memory profiling")
				flags.Parse(false, cmdArgs)
			}
			if cpuProf {
				if f, err := ioutil.TempFile("", "hockeypuck-cpuprof"); err == nil {
					defer f.Close()
					pprof.StartCPUProfile(f)
					defer pprof.StopCPUProfile()
				} else {
					log.Println("Warning: Failed to open tempfile for cpuprof:", err)
				}
			}
			if memProf {
				if f, err := ioutil.TempFile("", "hockeypuck-memprof"); err == nil {
					defer f.Close()
					defer pprof.WriteHeapProfile(f)
				} else {
					log.Println("Warning: Failed to open tempfile for cpuprof:", err)
				}
			}
			err := cmd.Main()
			die(err)
		}
	}
	newHelpCmd().Main()
}

type helpCmd struct {
	subCmd
}

func (c *helpCmd) Name() string { return "help" }

func (c *helpCmd) Desc() string { return "Display this help message" }

func (c *helpCmd) Main() error {
	fmt.Fprintln(os.Stderr, `Hockeypuck -- Public Keyserver
http://hockeypuck.github.io/

Hockeypuck is a public keyserver that supports the
HTTP Keyserver Protocol, as well as peering with SKS.

Basic commands:
`)
	for _, cmd := range cmds {
		fmt.Fprintf(os.Stderr, "  %s %s\t\t%s\n",
			filepath.Base(os.Args[0]), cmd.Name(), cmd.Desc())
	}
	return newUsageError(c, "hockeypuck usage")
}

func newHelpCmd() *helpCmd {
	return new(helpCmd)
}

type versionCmd struct {
	subCmd
}

func (c *versionCmd) Name() string { return "version" }

func (c *versionCmd) Desc() string { return "Display Hockeypuck version information" }

func (c *versionCmd) Main() error {
	fmt.Println(Version)
	return nil
}

func newVersionCmd() *versionCmd {
	return new(versionCmd)
}

type configuredCmd struct {
	subCmd
	configPath string
	configDir  string
	settings   *settings.Settings
}

func (c *configuredCmd) Main() error {
	if c.configPath == "" {
		defaultSettings := settings.Default()
		c.settings = &defaultSettings
		return nil
	}

	var err error
	c.configPath, err = filepath.Abs(c.configPath)
	if err != nil {
		return errgo.Mask(err)
	}

	contents, err := ioutil.ReadFile(c.configPath)
	if err != nil {
		return errgo.Mask(err)
	}

	c.settings, err = settings.Parse(string(contents))
	if err != nil {
		return errgo.Mask(err)
	}

	c.configDir = filepath.Dir(c.configPath)
	return nil
}
