#!/bin/bash -x

make -C precise/hockeypuck clean dev

juju deploy --repository=. --constraints "arch=amd64 mem=2G cpu-cores=4" local:precise/hockeypuck
juju deploy --constraints "arch=amd64 mem=4G cpu-cores=4 root-disk=100000" postgresql
juju add-relation hockeypuck postgresql:db
juju expose hockeypuck
