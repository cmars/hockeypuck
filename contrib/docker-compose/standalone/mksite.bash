#!/bin/bash

HERE=$(cd "$(dirname "$0")"; pwd)
set -eu

# Script to create or migrate a hockeypuck standalone deployment.

# This script should not overwrite existing modifications.
# To regenerate the .env file from scratch you must remove it first.

if [ ! -e "$HERE/.env" ]; then

POSTGRES_PASSWORD=$(head -c 30 /dev/urandom | base32 -w0)
cat >"$HERE/.env" <<EOF
###########################################################
## HOCKEYPUCK STANDALONE SITE CONFIGURATION TEMPLATE
## Edit this, then run ./mkconfig.bash
###########################################################

# This is the primary FQDN of your site
FQDN=keyserver.example.com
# Any extra FQDN aliases, space-separated
ALIAS_FQDNS=""
# A contact email address for the site operator (that's you!)
EMAIL=admin@example.com
# PGP encryption key for the above email address
FINGERPRINT=0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
# ACME Directory Resource URI (use Let's Encrypt if empty)
ACME_SERVER=

###########################################################
# You normally won't need to change anything below here
###########################################################

POSTGRES_USER=hkp
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
RELEASE=standalone
EOF
fi

if ! grep -q MIGRATION_HAPROXY_DONE "$HERE/.env"; then
# Migration 1: new haproxy configuration.

cat >>"$HERE/.env" <<EOF

# Parameterised default values for haproxy config
# You should only change these if you have modified docker-compose.yml to match

# Hosts and ports
PROMETHEUS_HOST_PORT=prometheus:9090
CERTBOT_HOST_PORT=certbot:80
KEYSERVER_HOST_PORT=hockeypuck:11371

# Paths and files
HAP_DHPARAM_FILE=/etc/letsencrypt/ssl-dhparams.pem
HAP_CONF_DIR=/usr/local/etc/haproxy
HAP_CACHE_DIR=/var/cache/haproxy
HAP_CERT_DIR=/etc/letsencrypt/live

# Remote URL for fetching tor exit relays list
TOR_EXIT_RELAYS_URL="https://www.dan.me.uk/torlist/?exit"

# MIGRATION_HAPROXY_DONE (DO NOT REMOVE THIS LINE!)
EOF

fi

chmod 600 "$HERE/.env"
