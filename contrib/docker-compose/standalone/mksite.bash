#!/bin/bash

HERE=$(cd $(dirname $0); pwd)
set -eu

[ ! -e "$HERE/.env" ]

POSTGRES_PASSWORD=$(head -c 30 /dev/urandom | base32 -w0)
cat >$HERE/.env <<EOF
###########################################################
## HOCKEYPUCK STANDALONE SITE CONFIGURATION TEMPLATE
## Edit this, then run ./mkconfig.bash
###########################################################

# This is the primary FQDN of your site
FQDN=keyserver.example.com
# Any extra FQDN aliases should be appended here, space-separated
ALIAS_FQDNS=
# A contact email address for the site operator (that's you!)
EMAIL=admin@example.com
# PGP encryption key for the above email address
FINGERPRINT=0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF

###########################################################
# You normally won't need to change anything below here
###########################################################

POSTGRES_USER=hkp
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
RELEASE=2.1.0
EOF
chmod 600 $HERE/.env
