.. title: Install from Source
.. slug: install-source
.. date: 2013/09/25 15:54:50
.. tags: 
.. link: 
.. description: 

Build Dependencies
==================

Go
--
Install Go 1.2 or newer from `golang.org <http://golang.org/doc/install>`_.

On Ubuntu, the Juju PPA contains more recent versions of the Go language
compiler and tools than the official releases::

  $ sudo apt-add-repository ppa:juju/golang
  $ sudo apt-get update
  $ sudo apt-get install golang-go

Set up your `Go language environment variables <http://golang.org/doc/code.html#GOPATH>`_.

DVCS Clients
------------
Go will need these DVCS clients installed in order to provision the source code
to Hockeypuck's package dependencies:

* Bazaar
* Git
* Mercurial

On Ubuntu::

  $ sudo apt-get install bzr git mercurial

Source & Dependencies
=====================

Check out the Hockeypuck sources, with all its package dependencies into your
Go development workspace with::

  $ go get -d -t github.com/hockeypuck/hockeypuck/...

Build
=====
In the hockeypuck project directory ($GOPATH/src/github.com/hockeypuck/hockeypuck)::

  $ make

will fetch third-party package dependencies, set them to the precise version
Hockeypuck requires, and compile Hockeypuck to .godeps/bin/hockeypuck.

To remove all the files created by the build, use::

  $ make all-clean

Install
=======

Binaries
--------
Copy the Hockeypuck binary, .godeps/bin/hockeypuck, into your $PATH.

Media
-----
Hockeypuck will need to access the static media files (Go HTML templates,
images, CSS, JS and fonts). These files will have been checked out into
$GOPATH/src/github.com/hockeypuck/hockeypuck/instroot/var/lib/hockeypuck/www in
the above steps. If Hockeypuck is run with the same $GOPATH environment
variable set, it will be able to automatically locate these files when running
the service.

Otherwise, you will need to set the hockeypuck.hkp.webroot configuration
setting to the installed location of these files.

Hacking
=======
Hockeypuck uses `gpm <https://github.com/pote/gpm>`_ to manage package
dependencies, setting them to a known good revision against which Hockeypuck
has been tested. To set the package dependencies in your $GOPATH to the
versions required for a proper, production-worthy build of Hockeypuck::

  $ scripts/gpm install

Then you will be able to compile hockeypuck with::

  $ go build github.com/hockeypuck/hockeypuck/cmd/hockeypuck

This is the preferred way to compile for development on Hockeypuck.

Next Steps
==========

Now you have compiled static Hockeypuck binaries in $GOPATH/bin, you're ready
to run. Move on to `Configuration </configuration.html>`_ to set up your
Hockeypuck service.
