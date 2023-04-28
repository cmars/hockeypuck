#!/bin/bash

set -eu

PGP_EXPORT=$(awk -F= '/^PGP_EXPORT=/ { print $2 }' .env | tail -1)

# bring deployment back up regardless of failures
cleanup() {
    docker-compose up -d
}
trap cleanup EXIT

docker-compose stop hockeypuck
docker-compose rm -f hockeypuck
docker-compose run --rm \
    --volume "${PGP_EXPORT:-/var/cache/hockeypuck}:/hockeypuck/export" \
    --entrypoint /bin/bash \
    hockeypuck -xe -c \
		'mkdir -p /hockeypuck/export/dump; find /hockeypuck/export/dump -type f -exec rm {} +; /hockeypuck/bin/hockeypuck-dump -config /hockeypuck/etc/hockeypuck.conf -path /hockeypuck/export/dump'
