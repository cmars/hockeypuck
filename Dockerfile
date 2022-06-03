FROM golang:buster as builder
LABEL io.hockeypuck.temp=true
RUN adduser builder --system --disabled-login
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get -y install build-essential postgresql-11 postgresql-server-dev-11 --no-install-recommends
COPY --chown=builder:root Makefile /hockeypuck/
COPY --chown=builder:root src /hockeypuck/src
ENV GOPATH=/hockeypuck
USER builder
WORKDIR /hockeypuck
RUN make lint test test-postgresql
RUN cd src/hockeypuck && go install hockeypuck/server/cmd/...


FROM debian:buster-slim
RUN mkdir -p /hockeypuck/bin /hockeypuck/lib /hockeypuck/etc /hockeypuck/data
COPY --from=builder /hockeypuck/bin /hockeypuck/bin
COPY contrib/templates /hockeypuck/lib/templates
COPY contrib/webroot /hockeypuck/lib/www
COPY contrib/bin/startup.sh /hockeypuck/bin/
VOLUME /hockeypuck/etc /hockeypuck/data
CMD ["/hockeypuck/bin/startup.sh"]
