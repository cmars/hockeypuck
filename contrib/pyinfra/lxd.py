# A LXD inventory that idempotently provisions LXD containers. You could
# probably do something similar with cloud APIs if so inclined.

import json
import os
from subprocess import check_output, check_call, CalledProcessError

containers=['hkp1', 'hkp2']
addrs=[]

def ensure_container(name):
    try:
        check_output(['lxc', 'info', name])
    except CalledProcessError:
        #lp_user = check_output(['bzr', 'lp-login']).decode().strip()
        lp_user = "cmars"
        check_call(['lxc', 'launch', 'ubuntu:bionic', name])
        check_call(['lxc', 'exec', name, '--', 'bash', '-c', 'while [ ! -f /var/lib/cloud/instance/boot-finished ]; do sleep 1; done'])
        check_call(['lxc', 'exec', name, '--', 'bash', '-c', 'sudo su - ubuntu -c "ssh-import-id {}"'.format(lp_user)])
    addrs.append(check_output(['lxc', 'exec', name, '--', 'bash', '-c', "ip addr show eth0 | awk '/inet / {print $2}' | sed 's_/.*__'"]).decode().strip())

for name in containers:
    ensure_container(name)

lxd_servers = [(addr, {'name': name, 'ssh_user': 'ubuntu', 'peers': [p for p in addrs if p != addr]}) for (name, addr) in zip(containers, addrs)]
