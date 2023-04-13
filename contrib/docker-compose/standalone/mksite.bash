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

# Advanced HAProxy configuration options

# Set this to the host:port that your HAProxy peers will see
#HAP_PEER_HOST_PORT=127.0.0.1:1395

# Set these to "port" or "host:port" to override the listening hostip/port(s)
#HAP_HTTP_HOST_PORT=80
#HAP_HTTPS_HOST_PORT=443
#HAP_HKP_HOST_PORT=11371

# Uncomment *at most one* of the BEHIND settings to trust an upstream proxy's request headers.
# This is vital so that rate limiting applies to the client's real IP and not the proxy's.
#
# Trust CF-Connecting-IP: headers
#HAP_BEHIND_CLOUDFLARE=true
# Trust X-Forwarded-For: headers
#HAP_BEHIND_PROXY=true

# Set this to e.g. /etc/letsencrypt in order to share certificates with the host.
# Note that the certbot container is responsible for renewing these.
#CERTBOT_CONF=certbot_conf

# MIGRATION_HAPROXY_DONE (DO NOT REMOVE THIS LINE!)
EOF

fi

chmod 600 "$HERE/.env"
