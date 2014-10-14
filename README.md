[![Build Status](https://travis-ci.org/hockeypuck/hockeypuck.svg?branch=master)](https://travis-ci.org/hockeypuck/hockeypuck)

# Hockeypuck: OpenPGP Key Server

Full Documentation: https://hockeypuck.github.io

## Developer Quickstart:

### Assuming that you have:
 * a recent (1.2 or newer) version of go installed
 * git, mercurial, bzr and build-essential

### Check out Hockeypuck sources (without compiling them yet)

```
 $ go get -d -t github.com/hockeypuck/hockeypuck
```

### Setting up dependencies

Update all the package dependencies in your $GOPATH to the versions supported
by Hockeypuck with:

```
 $ scripts/gpm install
```

At this point, you should be able to build, test and install.

### Build with the Makefile:

If you want to compile Hockeypuck but don't want to change the dependency
versions in your $GOPATH, use the Makefile build:

```
 $ cd $GOPATH/src/github.com/hockeypuck/hockeypuck
 $ make
```

Binary will be created at .godeps/bin/hockeypuck

