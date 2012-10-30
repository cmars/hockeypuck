
_GOPATH=gopath
GOPATH := $(CURDIR)/$(_GOPATH)

GO=go
HOCKEYPATH=$(GOPATH)/src/launchpad.net/hockeypuck

all: get \
	$(HOCKEYPATH)/cmd/hockeypuck-mgo/hockeypuck-mgo \
	$(HOCKEYPATH)/cmd/hockeypuck-mgo/hockeypuck-pq \
	$(HOCKEYPATH)/cmd/hockeypuck-load/hockeypuck-load

# 'get' resolves & fetches dependencies into our build $GOPATH
get: $(HOCKEYPATH)/mgo $(HOCKEYPATH)/pq

$(HOCKEYPATH)/mgo:
	@echo GOPATH is $(GOPATH)
	mkdir -p $(GOPATH)
	GOPATH="${GOPATH}" $(GO) get launchpad.net/hockeypuck/mgo

$(HOCKEYPATH)/pq:
	@echo GOPATH is $(GOPATH)
	mkdir -p $(GOPATH)
	GOPATH="${GOPATH}" $(GO) get launchpad.net/hockeypuck/pq

$(HOCKEYPATH)/cmd/hockeypuck-mgo/hockeypuck-%:
	cd $(HOCKEYPATH)/cmd/hockeypuck-$*; GOPATH="${GOPATH}" $(GO) build .

debsrc: debbin clean
	debuild -S

debbin:
	debuild -us -uc -i -b

clean:
	$(RM) $(HOCKEYPATH)/cmd/hockeypuck-mgo/hockeypuck-mgo
	$(RM) $(HOCKEYPATH)/cmd/hockeypuck-load/hockeypuck-load

srcclean:
	$(RM) -r $(GOPATH)
