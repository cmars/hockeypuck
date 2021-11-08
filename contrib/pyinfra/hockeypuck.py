import os
from subprocess import check_call

from pyinfra import host, local
from pyinfra.operations import apt, files, init, postgresql, server

os.chdir(os.path.dirname('./' + __file__))
cwd = os.path.abspath('.')
project_root = os.path.abspath('../..')

local.include('base.py')

files.sync(
    name='Sync templates',
    src=project_root+'/contrib/templates',
    dest='/var/lib/hockeypuck/templates',
    user='root',
    group='root',
    mode='644',
    delete=True,
    sudo=True,
)

files.sync(
    name='Sync webroot',
    src=project_root+'/contrib/webroot',
    dest='/var/lib/hockeypuck/www',
    user='root',
    group='root',
    mode='644',
    delete=True,
    sudo=True,
)

#os.environ['GOPATH'] = project_root
os.environ.update({'GOPATH': project_root})
check_call(['go', 'install', 'hockeypuck/...'])

files.sync(
    name='Install hockeypuck binaries',
    src=project_root+'/bin',
    dest='/usr/bin',
    mode='755',
    user='root',
    group='root',
    sudo=True,
)

files.put(
    name='Install hockeypuck service',
    src=project_root+'/debian/hockeypuck.service',
    dest='/etc/systemd/system/hockeypuck.service',
    mode='644',
    user='root',
    group='root',
    sudo=True,
)

files.template(
    name='Configure hockeypuck',
    src='hockeypuck.conf',
    dest='/etc/hockeypuck/hockeypuck.conf',
    mode='644',
    sudo=True,
    peers=host.data.peers,
)

postgresql.role(
    name='Create hockeypuck database role',
    role='hockeypuck',
    login=True,
    sudo=True,
    sudo_user='postgres',
)

postgresql.database(
    name='Create the hockeypuck database',
    database='hockeypuck',
    owner='hockeypuck',
    encoding='UTF8',
    sudo=True,
    sudo_user='postgres',
)

init.systemd(
    name='Start hockeypuck service',
    service='hockeypuck',
    running=True,
    restarted=True,
    enabled=True,
    daemon_reload=True,
    sudo=True,
)
