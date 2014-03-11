#!/bin/sh

set -x

if test -z $(which make); then apt-get install -y build-essential; fi

if test -z $(which go)
then
    apt-get install -y python-software-properties
    apt-add-repository -y ppa:juju/golang
    apt-get update -y
    apt-get install -y golang-go
fi

if test -z $(which bzr); then apt-get install -y bzr; fi
if test -z $(which hg); then apt-get install -y mercurial; fi
if test -z $(which git); then apt-get install -y git; fi
