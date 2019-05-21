#!/bin/bash

NODE_NAME=$1
SOURCE=$2
if [[ -z "${NODE_NAME}" || -z "${SOURCE}" ]]; then
	echo "Usage: $0 <node_name> <keyfiles_url>"
	exit 1
fi

juju action do ${NODE_NAME}-hockeypuck/0 fetch-keyfiles src=$SOURCE dest=/srv/hockeypuck/import
juju action do ${NODE_NAME}-hockeypuck/0 load-keyfiles path=/srv/hockeypuck/import

