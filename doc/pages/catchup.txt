.. title: Catching Up
.. slug: catchup
.. date: 2013/11/11 23:00:00
.. tags: 
.. link: 
.. description: 

Don't Panic
===========
If your Hockeypuck server is reconciling with other keyservers, and it
becomes unreachable for too long, it may not be able to catch up when it tries to
re-join its peers.

Obtain a new keyserver dump
===========================
Download a recent keyserver dump that will be closer to the contents of
your peers.

Drop Constraints
================
Drop all PostgreSQL foreign key, unique and primary key constraints for
bulk loading over an existing database.

Load Missing Keys
=================
Use ``hockeypuck load`` with your normal operating configuration file
to load the recent dump files. Hockeypuck will use the prefix tree to
skip over keys which have already been loaded into the database.

De-duplicate and Rebuild Constraints
====================================
We'll now need to rebuild the constraints we dropped earlier, with the
new key data appended to the PostgreSQL and prefix tree databases::

  $ hockeypuck db --config /path/to/hockeypuck.conf --dedup --create-constraints

Start It Up
===========
You should now be able to start the Hockeypuck service back up, and re-join
reconciliation with your peers.
