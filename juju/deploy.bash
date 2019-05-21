#!/bin/bash

NODE_NAME=$1
if [ -z "${NODE_NAME}" ]; then
	NODE_NAME=hkp1
fi

cat >${NODE_NAME}-config.yaml <<EOF
${NODE_NAME}-mongodb:
  dbpath: /mnt
EOF

juju deploy cs:~hockeypuck/trusty/hockeypuck ${NODE_NAME}-hockeypuck
juju deploy --config ${NODE_NAME}-config.yaml mongodb ${NODE_NAME}-mongodb
juju add-relation ${NODE_NAME}-mongodb ${NODE_NAME}-hockeypuck

juju deploy haproxy ${NODE_NAME}-haproxy
juju add-relation ${NODE_NAME}-haproxy:reverseproxy ${NODE_NAME}-hockeypuck

