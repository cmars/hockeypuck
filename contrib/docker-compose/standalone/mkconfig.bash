#!/bin/bash

# This script will not overwrite any existing config, to protect manual edits.
# To regenerate config files you must remove them first.

# Note that `set -a` causes all variables sourced from `.env` to be implicitly `export`ed.
# This is necessary for envsubst

HERE=$(cd "$(dirname "$0")"; pwd)
set -eua

[ -f "$HERE/.env" ] || { echo "Environment file not found; you must run ./mksite.bash first" ; exit 1; }

FQDN=$(awk -F= '/^FQDN=/ {print $2}' < "$HERE/.env" | tail -1)
FINGERPRINT=$(awk -F= '/^FINGERPRINT=/ {print $2; exit}' < "$HERE/.env" | tail -1)
RELEASE=$(awk -F= '/^RELEASE=/ {print $2; exit}' < "$HERE/.env" | tail -1)
POSTGRES_USER=$(awk -F= '/^POSTGRES_USER=/ {print $2; exit}' < "$HERE/.env" | tail -1)
POSTGRES_PASSWORD=$(awk -F= '/^POSTGRES_PASSWORD=/ {print $2; exit}' < "$HERE/.env" | tail -1)

# Check for migrations
if ! grep -q MIGRATION_3_DONE "$HERE/.env"; then
	cat <<EOF

-----------------------------------------------------------------------
WARNING: Site configuration migration is required before continuing.

Please run 'mksite.bash' to update your site configuration, and
then run this script again.
-----------------------------------------------------------------------

EOF
	exit 1
fi

[ ! -f "$HERE/hockeypuck/etc/hockeypuck.conf" ] &&
	envsubst '$FQDN:$FINGERPRINT:$RELEASE:$POSTGRES_USER:$POSTGRES_PASSWORD' \
	< "$HERE/hockeypuck/etc/hockeypuck.conf.tmpl" > "$HERE/hockeypuck/etc/hockeypuck.conf"
