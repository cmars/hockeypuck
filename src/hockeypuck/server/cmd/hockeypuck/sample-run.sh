#!/bin/bash -x

killall hockeypuck
rm -rf ptree-peer*
rm -rf .ptree-peer*

set -e

go build

createdb hkp-peer1
createdb hkp-peer2

./hockeypuck -config sample-peer1.conf -cpuprof -memprof &
./hockeypuck -config sample-peer2.conf -cpuprof -memprof &
