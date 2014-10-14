
PACKAGE=github.com/hockeypuck/hockeypuck
VERSION=$(shell head -1 debian/changelog | sed 's/.*(//;s/).*//;')
CURRENT=$(shell git rev-parse --short HEAD)

all: compile

.godeps:
	bash -c "source scripts/gvp; scripts/gpm install"

compile: .godeps
	go install -ldflags "-X ${PACKAGE}.Version ${VERSION}" ${PACKAGE}/cmd/hockeypuck
	make -C doc fakebuild

sdist: .godeps

debs: debsrc debbin

debsrc: sdist
	debuild -S -k0x879CF8AA8DDA301A

debbin:
	debuild -us -uc -i -b

clean:
	make -C doc clean

src-clean:
	$(RM) -r .godeps

pkg-clean:
	rm -f ../hockeypuck_*.deb ../hockeypuck_*.dsc ../hockeypuck_*.changes ../hockeypuck_*.build ../hockeypuck_*.tar.gz ../hockeypuck_*.upload

all-clean: clean src-clean pkg-clean

.PHONY: all compile sdist debs debsrc debbin clean src-clean pkg-clean all-clean
