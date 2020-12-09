import os
from subprocess import check_call

from pyinfra import host, local
from pyinfra.operations import apt, files, init, postgresql, server

os.chdir(os.path.dirname('./' + __file__))
cwd = os.path.abspath('.')
project_root = os.path.abspath('../..')

SUDO=True

if host.data.name == 'hkp1':
    server.shell(commands=[
        'systemctl stop hockeypuck || true',
        'mkdir -p /data/dump',
        'rsync -avr rsync://rsync.cyberbits.eu/sks/dump/hkp-dump-000*.pgp /data/dump',
        'sudo su - hockeypuck -c "hockeypuck-load -config /etc/hockeypuck/hockeypuck.conf /data/dump/*.pgp"',
        'systemctl start hockeypuck',
    ])
