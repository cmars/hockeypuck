FROM golang:1.12 AS builder
COPY src /hockeypuck/src
ENV GOPATH=/hockeypuck
WORKDIR /hockeypuck/src
RUN go vet ./...
RUN go install ./hockeypuck/server/cmd/...

FROM ubuntu:18.04
RUN mkdir -p /hockeypuck/{bin,lib,etc,data}
COPY --from=builder /hockeypuck/bin /hockeypuck/bin
COPY contrib/templates /hockeypuck/lib/templates
VOLUME /hockeypuck/etc /hockeypuck/data
ENTRYPOINT ["/hockeypuck/bin/hockeypuck", "-config", "/hockeypuck/etc/hockeypuck.conf"]
