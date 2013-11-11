
#GODEPS=launchpad.net/godeps
GODEPS=github.com/cmars/godeps

all: compile

compile:
	go build launchpad.net/hockeypuck/...
	go install launchpad.net/hockeypuck/...
	make -C doc

godeps: require-godeps apply-godeps

fmt:
	gofmt -w=true ./...

debs: debbin debsrc

debsrc: debbin clean
	debuild -S -k0x879CF8AA8DDA301A

debbin: freeze-build
	debuild -us -uc -i -b

freeze-build:
	GOPATH=$(shell pwd)/build go get launchpad.net/hockeypuck/...
	GOPATH=$(shell pwd)/build make apply-godeps

freeze-godeps: require-godeps
	${GOPATH}/bin/godeps $(go list launchpad.net/hockeypuck/...) > dependencies.tsv

apply-godeps: require-godeps
	${GOPATH}/bin/godeps -u dependencies.tsv

require-godeps:
	go get ${GODEPS}
	go install ${GODEPS}

clean:
	rm -rf build/bin build/pkg

src-clean:
	rm -rf build

.PHONY: all compile godeps fmt debs debsrc debbin freeze-build freeze-godeps apply-godeps require-godeps clean src-clean
