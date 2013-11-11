
_GOPATH=gopath
GOPATH := $(CURDIR)/$(_GOPATH)

GO=go
HOCKEYPATH=$(GOPATH)/src/launchpad.net/hockeypuck

all:
	mkdir -p $(GOPATH)/src/launchpad.net
	([ ! -e "$(GOPATH)/src/launchpad.net/hockeypuck" ] && [ -z "$(DEB_BUILD_ARCH_OS)" ]) && ln -s "$(CURDIR)" "$(GOPATH)/src/launchpad.net/hockeypuck" || true
	GOPATH="${GOPATH}" $(GO) get launchpad.net/hockeypuck/cmd/hockeypuck
	GOPATH="${GOPATH}" $(GO) install launchpad.net/hockeypuck/cmd/hockeypuck
	make -C doc

fmt:
	gofmt -w=true ./...

debsrc: debbin clean
	debuild -S -k0x879CF8AA8DDA301A

debbin:
	debuild -us -uc -i -b

get-deps:
	godeps $(go list launchpad.net/hockeypuck/...) > dependencies.tsv

set-deps:
	godeps -u dependencies.tsv

clean:
	go clean ./...
	$(RM) -r $(GOPATH)/bin $(GOPATH)/pkg

srcclean:
	$(RM) -r $(GOPATH)
