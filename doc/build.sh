#!/bin/bash -e

rm -rf output

if [ -x "/usr/bin/nikola" ]; then
	nikola build
else
	mkdir output
	cp -r pages/* output
fi
