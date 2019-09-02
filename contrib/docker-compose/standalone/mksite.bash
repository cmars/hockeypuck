#!/bin/bash

HERE=$(cd $(dirname $0); pwd)
set -eu

[ ! -e "$HERE/site.profile" ]

POSTGRES_PASSWORD=$(head -c 30 /dev/urandom | base32 -w0)
cat >$HERE/site.profile <<EOF
export FQDN=hockeypuck.io
export EMAIL=hockeypuck@hockeypuck.io
export POSTGRES_USER="hkp"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
EOF
chmod 600 $HERE/site.profile
