#!/bin/bash

HERE=$(cd $(dirname $0); pwd)
set -eu

[ ! -e "$HERE/site.profile" ]

POSTGRES_PASSWORD=$(head -c 30 /dev/urandom | base32 -w0)
cat >$HERE/site.profile <<EOF
FQDN=hockeypuck.io
EMAIL=hockeypuck@\$FQDN
POSTGRES_USER="hkp"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
EOF
chmod 600 $HERE/site.profile
