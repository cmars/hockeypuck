FROM golang:buster as builder
RUN adduser builder --system --disabled-login
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get -y install build-essential postgresql-11 postgresql-server-dev-11 --no-install-recommends
COPY --chown=builder:root . /hockeypuck
ENV GOPATH=/hockeypuck
USER builder
WORKDIR /hockeypuck
RUN make lint test test-postgresql
RUN cd src/hockeypuck && go install hockeypuck/server/cmd/...


FROM debian:buster-slim
RUN mkdir -p /hockeypuck/bin /hockeypuck/lib /hockeypuck/etc /hockeypuck/data
COPY --from=builder /hockeypuck/bin /hockeypuck/bin
COPY --from=builder /hockeypuck/contrib/templates /hockeypuck/lib/templates
COPY --from=builder /hockeypuck/contrib/webroot /hockeypuck/lib/www
VOLUME /hockeypuck/etc /hockeypuck/data
CMD ["/hockeypuck/bin/hockeypuck", "-config", "/hockeypuck/etc/hockeypuck.conf"]
