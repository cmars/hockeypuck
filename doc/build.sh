#!/bin/bash -e

if [ -x "/usr/bin/nikola" ]; then
	nikola build
else
	mkdir output
	cp -r pages/* output
fi
