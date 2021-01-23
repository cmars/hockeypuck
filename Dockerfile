FROM golang:1.15 AS toolchain

FROM ubuntu:18.04 as builder
RUN adduser builder --system --disabled-login
COPY --from=toolchain /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:/usr/lib/postgresql/10/bin:${PATH}"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get -y install build-essential postgresql-10 postgresql-server-dev-10 ca-certificates --no-install-recommends
COPY --chown=builder:root . /hockeypuck
ENV GOPATH=/hockeypuck
USER builder
WORKDIR /hockeypuck
RUN make lint test test-postgresql
RUN go install hockeypuck/server/cmd/...
ENTRYPOINT ["/bin/bash"]


FROM ubuntu:18.04
RUN apt-get update -qq && apt-get dist-upgrade -y && apt-get -y install ca-certificates --no-install-recommends
RUN mkdir -p /hockeypuck/bin /hockeypuck/lib /hockeypuck/etc /hockeypuck/data
COPY --from=builder /hockeypuck/bin /hockeypuck/bin
COPY --from=builder /hockeypuck/contrib/templates /hockeypuck/lib/templates
COPY --from=builder /hockeypuck/contrib/webroot /hockeypuck/lib/www
VOLUME /hockeypuck/etc /hockeypuck/data
ENTRYPOINT ["/hockeypuck/bin/hockeypuck", "-config", "/hockeypuck/etc/hockeypuck.conf"]
