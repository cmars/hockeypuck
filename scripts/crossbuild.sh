#!/bin/bash -ex

#
# This script depends on a Go cross-compilation setup as described here:
# http://dave.cheney.net/2012/09/08/an-introduction-to-cross-compilation-with-go
# 
. $HOME/local/bin/golang-crosscompile

if [ -z "$1" ]; then
	PLATFORMS="darwin-386 darwin-amd64 freebsd-386 freebsd-amd64 linux-386 linux-amd64 windows-386 windows-amd64"
else
	PLATFORMS=$1
fi

GOPATH=$(pwd)/gopath
rm -rf $(GOPATH)

APPS="launchpad.net/hockeypuck/cmd/hockeypuck-mgo launchpad.net/hockeypuck/cmd/hockeypuck-load"

for platform in $PLATFORMS;
do
	for app in $APPS;
	do
		go-$platform get $app
		go-$platform install $app
	done
done

BUILD=$(pwd)/build
DIST=$(pwd)/dist
rm -rf $BUILD
mkdir -p $DIST

host_platform=$(go env GOOS)-$(go env GOARCH)

for platform in $PLATFORMS;
do
	platform_bin=$(echo $platform | sed 's/-/_/')
	tar -C instroot -cvf $DIST/hockeypuck-$platform.tar .
	mkdir -p $BUILD/$platform/usr/bin
	if [[ $platform != $host_platform ]]; then
		cp -r $GOPATH/bin/$platform_bin/* $BUILD/$platform/usr/bin
	else
		cp -r $GOPATH/bin/hockeypuck-* $BUILD/$platform/usr/bin
	fi
	tar -C $BUILD/$platform -rvf $DIST/hockeypuck-$platform.tar ./usr/bin
	gzip -9f $DIST/hockeypuck-$platform.tar
done

#rm -rf $BUILD

exit 0
