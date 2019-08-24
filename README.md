# Hockeypuck

Hockeypuck is an OpenPGP public keyserver. 

# Building

## Any platform/arch

With Go 1.12 installed, from this directory:

    export GOPATH=$(pwd)
    go build ./src/hockeypuck/server/cmd/...
    go install ./src/hockeypuck/server/cmd/...

Hockeypuck binaries will be in `bin/`.

## Ubuntu package maintainers

To locally build the hockeypuck binaries:

    make install-build-depends
    make

# Releases

## Ubuntu package maintainers

In order to release a new version of hockeypuck:

    make dch
    git add debian/changelog
    git commit -m 'x.y.z release'
    git tag -s -u <keyid> -m 'x.y.z release' x.y.z
    git push --tags
    make deb-src
    dput <your ppa> ../hockeypuck\_x.y.z\_source.changes

Where `x.y.z` is the appropriate version number.
This will upload the debian source package to the Launchpad PPA for building.

# Running

## Quick start with Docker

Easiest way to run Hockeypuck locally is with `docker-compose`:

    docker-compose up

# About

Copyright 2019, The Hockeypuck Developers; see CONTRIBUTORS and LICENSE for details.

## Vendored Dependencies

The dependencies for this project are managed via Go modules.
To update the dependencies run:

    cd src
    go get -u -m
    go mod vendor

After which you can ensure that the code continues to build and
that the tests still pass.

