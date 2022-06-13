#!/bin/bash

# Note that `set -a` causes all variables sourced from `.env` to be implicitly `export`ed.
# This is necessary for envsubst

HERE=$(cd $(dirname $0); pwd)
set -eua

[ -e "$HERE/.env" ]
. "$HERE/.env"

envsubst '$FQDN:$FINGERPRINT:$RELEASE:$POSTGRES_USER:$POSTGRES_PASSWORD' \
	< "$HERE/hockeypuck/etc/hockeypuck.conf.tmpl" > "$HERE/hockeypuck/etc/hockeypuck.conf"
envsubst '$FQDN:$ALIAS_FQDNS' \
	< "$HERE/nginx/conf.d/hockeypuck.conf.tmpl" > "$HERE/nginx/conf.d/hockeypuck.conf"
