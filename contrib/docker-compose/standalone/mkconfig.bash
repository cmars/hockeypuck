#!/bin/bash

# This script will not overwrite any existing config, to protect manual edits.
# To regenerate config files you must remove them first.

# Note that `set -a` causes all variables sourced from `.env` to be implicitly `export`ed.
# This is necessary for envsubst

HERE=$(cd "$(dirname "$0")"; pwd)
set -eua

[ -e "$HERE/.env" ]
. "$HERE/.env"

# Check for migrations
if ! grep -q MIGRATION_HAPROXY_DONE "$HERE/.env"; then
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

# Populate the LOCAL portions of the HAProxy configuration
for template in "$HERE"/haproxy/etc/haproxy.d/*LOCAL*.cfg.tmpl; do
	config="$HERE/haproxy/etc/haproxy.d/$(basename "$template" .tmpl)"
	[ ! -f "$config" ] &&
		cp "$template" "$config"
done

[ ! -d "$HERE/haproxy/etc/lists" ] &&
	mkdir "$HERE/haproxy/etc/lists"

# Make sure that black/whitelists exist, even if empty
for file in blacklist whitelist; do
	[ ! -f "$HERE/haproxy/etc/lists/$file.list" ] &&
		touch "$HERE/haproxy/etc/lists/$file.list"
done

# And populate the aliases map
for alias in ${ALIAS_FQDNS:-}; do
	echo "$alias $FQDN"
done > "$HERE"/haproxy/etc/lists/aliases.map
