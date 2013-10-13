.. title: Install from tarball
.. slug: install-tarball
.. date: 2013/09/25 21:15:00
.. tags: 
.. link: 
.. description: 

Download
========
Download a `gzip-compressed tar archive release from Launchpad <https://launchpad.net/hockeypuck/+download>`_ for your operating system and architecture. Generally, Hockeypuck can be built for any Unix-like platform that the Go language compiler and linker supports.

Install
=======

Extract into '/'
----------------
The archive can be extracted into '/'. This will preserve the path references in the archived files.

Chroot
------
For added security, you could extract into an arbitrary path and chroot the Hockeypuck process. If you do this, consider the implications for a local UNIX domain socket connection to PostgreSQL.

Similarly, binary distributions could be run within LXC (Linux containers).

Packaging
=========
The Hockeypuck binary archive distributions could be a useful starting point to build packages for other operating system distributions.

Next Steps
==========
Now you have installed static Hockeypuck binaries and the starting point example configuration, move on to `Configuration </configuration.html>`_ to set up your Hockeypuck service.
