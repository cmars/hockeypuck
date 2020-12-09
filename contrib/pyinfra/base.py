import os
from subprocess import check_call

from pyinfra import host, local
from pyinfra.operations import apt, files, init, postgresql, server

os.chdir(os.path.dirname('./' + __file__))
cwd = os.path.abspath('.')
project_root = os.path.abspath('../..')

server.user(
    user='hockeypuck',
    home='/var/lib/hockeypuck',
    system=True,
    sudo=True,
)

for d in ('templates', 'www'):
    files.directory(
        path='/var/lib/hockeypuck/'+d,
        user='hockeypuck',
        group='hockeypuck',
        sudo=True,
    )

files.directory(
    path='/etc/hockeypuck',
    user='root',
    group='root',
    sudo=True,
)

apt.packages(
    name='Install postgresql',
    packages=['postgresql'],
    latest=True,
    sudo=True,
)

