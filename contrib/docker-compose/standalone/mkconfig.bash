#!/bin/bash

HERE=$(cd $(dirname $0); pwd)
set -eux

[ -e "$HERE/site.profile" ]
. $HERE/site.profile

sed 's/POSTGRES_USER/'$POSTGRES_USER'/;s/POSTGRES_PASSWORD/'$POSTGRES_PASSWORD'/;' \
	$HERE/hockeypuck/etc/hockeypuck.conf.tmpl > $HERE/hockeypuck/etc/hockeypuck.conf
sed 's/FQDN/'$FQDN'/' \
	$HERE/nginx/conf.d/hockeypuck.conf.tmpl > $HERE/nginx/conf.d/hockeypuck.conf
