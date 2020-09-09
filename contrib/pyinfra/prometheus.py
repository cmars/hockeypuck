import os
from subprocess import check_call

from pyinfra import host
from pyinfra.modules import apt, files, init, postgresql, server

os.chdir(os.path.dirname('./' + __file__))
cwd = os.path.abspath('.')
project_root = os.path.abspath('../..')

apt.packages(
    {'Install prometheus'},
    ['prometheus'],
    latest=True,
    sudo=True,
)

files.put(
    {'Install prometheus config'},
    'prometheus.yml',
    '/etc/prometheus/prometheus.yml',
    mode='644',
    user='root',
    group='root',
    sudo=True,
)
 
init.systemd(
    {'Restart prometheus service'},
    'prometheus',
    running=True,
    restarted=True,
    enabled=True,
    sudo=True,
)
