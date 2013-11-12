#!/bin/bash -x

juju deploy --repository=. local:precise/sks
juju expose sks
