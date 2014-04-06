#!/bin/bash -e

rm -rf output

if [ -x "/usr/bin/nikola" ]; then
	nikola build
else
	$(dirname $0)/fakebuild.sh
fi
