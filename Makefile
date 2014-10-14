
PACKAGE=github.com/hockeypuck/hockeypuck
VERSION=$(shell head -1 debian/changelog | sed 's/.*(//;s/).*//;')
CURRENT=$(shell git rev-parse --short HEAD)

all: compile

deps:
	scripts/gpm install

compile: deps
	go install -ldflags "-X ${PACKAGE}.Version ${VERSION}" ${PACKAGE}/cmd/hockeypuck
	make -C doc fakebuild

sdist:
	bash -c "source scripts/gvp; \
	scripts/gpm install"

debs: debsrc debbin

debsrc: sdist
	debuild -S -k0x879CF8AA8DDA301A

debbin:
	debuild -us -uc -i -b

clean:
	$(RM) -r .godeps
	make -C doc clean

pkg-clean:
	rm -f ../hockeypuck_*.deb ../hockeypuck_*.dsc ../hockeypuck_*.changes ../hockeypuck_*.build ../hockeypuck_*.tar.gz 

all-clean: clean pkg-clean

.PHONY: all compile godeps fmt debs debsrc debbin freeze-build freeze-godeps apply-godeps require-godeps clean src-clean pkg-clean build all-clean
