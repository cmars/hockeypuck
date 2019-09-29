#!/bin/bash

HERE=$(cd $(dirname $0); pwd)
set -euo pipefail

cd $HERE/..

RELEASE=$1

PRIOR_RELEASE=$(git tag | sort -V | tail -n1)

gbp dch -s $PRIOR_RELEASE -S -N $RELEASE

docker build --no-cache -t docker.pkg.github.com/hockeypuck/hockeypuck/hockeypuck:$RELEASE .

git add debian/changelog
git commit -m "Release $RELEASE"

git tag -S $RELEASE

