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

# TODO: pass ALIAS_FQDNS, aliases currently need to be added to haproxy.cfg by hand
# envsubst cannot iterate over a list
[ ! -f "$HERE/haproxy/etc/haproxy.cfg" ] &&
	envsubst '$FQDN:$PROMETHEUS_HOST_PORT:$CERTBOT_HOST_PORT:$KEYSERVER_HOST_PORT:$HAP_CONF_DIR:$HAP_CACHE_DIR:$HAP_CERT_DIR:$HAP_DHPARAM_FILE' \
	< "$HERE/haproxy/etc/haproxy.cfg.tmpl" > "$HERE/haproxy/etc/haproxy.cfg"

# Make sure that black/whitelists exist, even if empty
for file in blacklist whitelist; do
	[ ! -d "$HERE/haproxy/etc/lists" ] &&
		mkdir "$HERE/haproxy/etc/lists"
	[ ! -f "$HERE/haproxy/etc/lists/$file.list" ] &&
		touch "$HERE/haproxy/etc/lists/$file.list"
done

if [[ ${ALIAS_FQDNS:-} ]]; then
	cat <<EOF
WARNING: you have ALIAS_FQDNS set, but this script cannot yet configure them in haproxy
You MUST edit haproxy/etc/haproxy.cfg to add them one per line, near the following:

EOF
	grep -nC2 ALIAS_FQDN "$HERE/haproxy/etc/haproxy.cfg" || true
fi
