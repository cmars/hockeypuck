
_GOPATH=gopath
GOPATH := $(CURDIR)/$(_GOPATH)

GO=go
HOCKEYPATH=$(GOPATH)/src/launchpad.net/hockeypuck

all:
	mkdir -p $(GOPATH)/src/launchpad.net/hockeypuck
	rsync -aP --exclude $(GOPATH) $(CURDIR)/ $(GOPATH)/src/launchpad.net/hockeypuck/
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
