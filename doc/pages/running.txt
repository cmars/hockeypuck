.. title: Running
.. slug: running
.. date: 2013/11/11 23:00:00
.. tags: 
.. link: 
.. description: 

From the command-line
=====================
Start serving HKP requests and reconciling with peers from the command line::

  $ hockeypuck run --config /path/to/hockeypuck.conf

Logs and messages are written to standard output/error.

Upstart
=======
Ubuntu packaging installs an upstart service for Hockeypuck::

  $ service hockeypuck start

However, it is configured to start after postgresql starts on the local system.

System V Init
=============
A traditional Sys-V init script is also provided, based on the Debian skeleton script.
