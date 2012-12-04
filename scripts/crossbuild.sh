#!/bin/bash -ex

#
# This script depends on a Go cross-compilation setup as described here:
# http://dave.cheney.net/2012/09/08/an-introduction-to-cross-compilation-with-go
# 
. $HOME/local/bin/golang-crosscompile

if [ -z "$1" ]; then
	PLATFORMS="darwin-386 darwin-amd64 freebsd-386 freebsd-amd64 linux-amd64 windows-386 windows-amd64"
else
	PLATFORMS=$1
fi

GOPATH=$(pwd)/gopath

APPS="launchpad.net/hockeypuck/cmd/hockeypuck-mgo launchpad.net/hockeypuck/cmd/hockeypuck-load"

for platform in $PLATFORMS;
do
	for app in $APPS;
	do
		go-$platform get $app
		go-$platform install $app
	done
done

exit 0
