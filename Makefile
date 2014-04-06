
PACKAGE=github.com/hockeypuck/hockeypuck
GODEPS=launchpad.net/godeps
VERSION=$(shell head -1 debian/changelog | sed 's/.*(//;s/).*//;')

all: compile

compile:
	GOPATH=$(shell pwd)/build go install -ldflags "-X ${PACKAGE}.Version ${VERSION}" ${PACKAGE}/cmd/hockeypuck
	make -C doc fakebuild

build:
	GOPATH=$(shell pwd)/build go get ${PACKAGE}/...
	GOPATH=$(shell pwd)/build make godeps compile

godeps: require-godeps apply-godeps

fmt:
	gofmt -w=true ./...

debs: debbin debsrc

debsrc: debbin clean
	debuild -S -k0x879CF8AA8DDA301A

debbin: freeze-build
	debuild -us -uc -i -b

freeze-build:
	GOPATH=$(shell pwd)/build go get ${PACKAGE}/...
	GOPATH=$(shell pwd)/build make apply-godeps

freeze-godeps: require-godeps
	${GOPATH}/bin/godeps $(go list ${PACKAGE}/...) > dependencies.tsv

apply-godeps: require-godeps
	${GOPATH}/bin/godeps -u dependencies.tsv

require-godeps:
	go get -u ${GODEPS}
	go install ${GODEPS}

clean:
	rm -rf build/bin build/pkg
	make -C doc clean

src-clean:
	rm -rf build

pkg-clean:
	rm -f ../hockeypuck_*.deb ../hockeypuck_*.dsc ../hockeypuck_*.changes ../hockeypuck_*.build ../hockeypuck_*.tar.gz 

all-clean: clean src-clean pkg-clean

.PHONY: all compile godeps fmt debs debsrc debbin freeze-build freeze-godeps apply-godeps require-godeps clean src-clean pkg-clean build all-clean
