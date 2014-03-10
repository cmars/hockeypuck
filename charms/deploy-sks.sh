#!/bin/bash -x

juju deploy --repository=. --constraints 'arch=amd64 mem=2G cpu-cores=2 root-disk=50000' local:precise/sks
juju expose sks
