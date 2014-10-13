
PACKAGE=github.com/hockeypuck/hockeypuck
GODEP=github.com/tools/godep
GO=godep go
VERSION=$(shell head -1 debian/changelog | sed 's/.*(//;s/).*//;')
CURRENT=$(shell git rev-parse --short HEAD)

all: compile

compile: require-godep
	godep go install -ldflags "-X ${PACKAGE}.Version ${VERSION}" ${PACKAGE}/cmd/hockeypuck
	make -C doc fakebuild

build:
	GOPATH=$(shell pwd)/build go get -d ${PACKAGE}/...
	GOPATH=$(shell pwd)/build make godeps compile

godep: require-godep

fmt:
	gofmt -w=true ./...

debs: debbin debsrc

debsrc: debbin clean
	debuild -S -k0x879CF8AA8DDA301A

debbin: freeze-build
	debuild -us -uc -i -b

require-godep:
	go get ${GODEP}

clean:
	rm -rf build/bin build/pkg
	make -C doc clean

src-clean:
	rm -rf build

pkg-clean:
	rm -f ../hockeypuck_*.deb ../hockeypuck_*.dsc ../hockeypuck_*.changes ../hockeypuck_*.build ../hockeypuck_*.tar.gz 

all-clean: clean src-clean pkg-clean

.PHONY: all compile godeps fmt debs debsrc debbin freeze-build freeze-godeps apply-godeps require-godeps clean src-clean pkg-clean build all-clean
