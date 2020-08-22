import os
from subprocess import check_call

from pyinfra import host
from pyinfra.modules import apt, files, init, postgresql, server

os.chdir(os.path.dirname('./' + __file__))
cwd = os.path.abspath('.')
project_root = os.path.abspath('../..')

server.user(
    'hockeypuck',
    home='/var/lib/hockeypuck',
    system=True,
    sudo=True,
)

create_install_dir = files.directory(
    '/var/lib/hockeypuck',
    user='hockeypuck',
    group='hockeypuck',
    sudo=True,
)

files.directory(
    '/etc/hockeypuck',
    user='root',
    group='root',
    sudo=True,
)

files.sync(
    {'Sync templates'},
    project_root+'/contrib/templates',
    '/var/lib/hockeypuck/templates',
    user='root',
    group='root',
    mode='644',
    delete=True,
    sudo=True,
)

files.sync(
    {'Sync webroot'},
    project_root+'/contrib/webroot',
    '/var/lib/hockeypuck/www',
    user='root',
    group='root',
    mode='644',
    delete=True,
    sudo=True,
)

check_call(['go', 'install', 'hockeypuck/...'],
           cwd=project_root)
files.sync(
    {'Install hockeypuck binaries'},
    project_root+'/bin',
    '/usr/bin',
    mode='755',
    user='root',
    group='root',
    sudo=True,
)

files.put(
    {'Install hockeypuck service'},
    project_root+'/debian/hockeypuck.service',
    '/etc/systemd/system/hockeypuck.service',
    mode='644',
    user='root',
    group='root',
    sudo=True,
)

files.template(
    {'Configure hockeypuck'},
    'hockeypuck.conf',
    '/etc/hockeypuck/hockeypuck.conf',
    mode='644',
    sudo=True,
    peers=host.data.peers,
)

apt.packages(
    {'Install postgresql'},
    ['postgresql'],
    latest=True,
    sudo=True,
)

postgresql.role(
    {'Create hockeypuck database role'},
    'hockeypuck',
    login=True,
    sudo=True,
    sudo_user='postgres',
)

postgresql.database(
    {'Create the hockeypuck database'},
    'hockeypuck',
    owner='hockeypuck',
    encoding='UTF8',
    sudo=True,
    sudo_user='postgres',
)

init.systemd(
    {'Start hockeypuck service'},
    'hockeypuck',
    running=True,
    restarted=True,
    enabled=True,
    daemon_reload=True,
    sudo=True,
)
