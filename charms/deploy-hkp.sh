#!/bin/bash -x

juju deploy --repository=. local:precise/hockeypuck
juju deploy postgresql
juju add-relation hockeypuck postgresql:db
juju expose hockeypuck
