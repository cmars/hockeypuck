
_GOPATH=gopath
GOPATH := $(CURDIR)/$(_GOPATH)

GO=go
HOCKEYPATH=$(GOPATH)/src/launchpad.net/hockeypuck

all: get $(HOCKEYPATH)/cmd/hockeypuck/hockeypuck

get: $(HOCKEYPATH)/mgo

$(HOCKEYPATH)/mgo:
	@echo GOPATH is $(GOPATH)
	mkdir -p $(GOPATH)
	GOPATH="${GOPATH}" $(GO) get launchpad.net/hockeypuck/mgo

$(HOCKEYPATH)/cmd/hockeypuck/hockeypuck:
	cd $(HOCKEYPATH)/cmd/hockeypuck; GOPATH="${GOPATH}" $(GO) build .

debsrc: debbin
	debuild -S

debbin:
	debuild -us -uc -i -b

clean:
	$(RM) $(HOCKEYPATH)/cmd/hockeypuck/hockeypuck
