
_GOPATH=debian/_gopath
GOPATH := $(CURDIR)/$(_GOPATH)

GO=go
HOCKEYPATH=debian/_gopath/src/launchpad.net/hockeypuck

all: get $(HOCKEYPATH)/cmd/hockeypuck/hockeypuck

get:
	@echo GOPATH is $(GOPATH)
	mkdir -p $(GOPATH)
	GOPATH="${GOPATH}" $(GO) get launchpad.net/hockeypuck/pq

$(HOCKEYPATH)/cmd/hockeypuck/hockeypuck:
	cd $(HOCKEYPATH)/cmd/hockeypuck; GOPATH="${GOPATH}" $(GO) build .

clean:
	$(RM) $(HOCKEYPATH)/cmd/hockeypuck/hockeypuck

fetch-clean:
	$(RM) -r $(_GOPATH)
