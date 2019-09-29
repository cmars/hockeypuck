#!/bin/bash

HERE=$(cd $(dirname $0); pwd)
set -euo pipefail

cd $HERE/..

PRIOR_RELEASE=$(git tag | sort -V | tail -n1)

docker push docker.pkg.github.com/hockeypuck/hockeypuck/hockeypuck:$PRIOR_RELEASE

