# pyinfra deployment of Hockeypuck

This directory contains a pyinfra deployment of Hockeypuck.

See https://pyinfra.com/ for more information. Basically, pyinfra is a simple
orchestrator, similar to Ansible, but everything is plain and simple Python
instead of layers of YAML. In my experience, it performs much faster than
Ansible and is really easy to work with. Great for setup and teardown of cloud
integration tests, and deploying "small software".

If you have a Launchpad account (used for ssh-import-id) and LXD installed
locally, you can try:

`pyinfra lxd.py hockeypuck.py`

from here to deploy a couple of Hockeypuck servers running in LXD containers.

