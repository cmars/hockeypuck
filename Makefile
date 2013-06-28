
_GOPATH=gopath
GOPATH := $(CURDIR)/$(_GOPATH)

GO=go
HOCKEYPATH=$(GOPATH)/src/launchpad.net/hockeypuck

all:
	mkdir -p $(GOPATH)/src/launchpad.net
	([ ! -e "$(GOPATH)/src/launchpad.net/hockeypuck" ] && [ -z "$(DEB_BUILD_ARCH_OS)" ]) && ln -s "$(CURDIR)" "$(GOPATH)/src/launchpad.net/hockeypuck" || true
	GOPATH="${GOPATH}" $(GO) get launchpad.net/hockeypuck/cmd/hockeypuck-mgo
	GOPATH="${GOPATH}" $(GO) get launchpad.net/hockeypuck/cmd/hockeypuck-load
	GOPATH="${GOPATH}" $(GO) install launchpad.net/hockeypuck/cmd/hockeypuck-mgo
	GOPATH="${GOPATH}" $(GO) install launchpad.net/hockeypuck/cmd/hockeypuck-load

fmt:
	gofmt -w=true .

debsrc: debbin clean
	debuild -S

debbin:
	debuild -us -uc -i -b

clean:
	$(RM) -r $(GOPATH)/bin $(GOPATH)/pkg

srcclean:
	$(RM) -r $(GOPATH)
