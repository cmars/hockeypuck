.. title: Pre-populating Hockeypuck
.. slug: pre-populating
.. date: 2013/10/02 11:13:48
.. tags: 
.. link: 
.. description: 


If you want Hockeypuck to peer with other keyservers, you will need
to pre-populate your Hockeypuck instance to share as many public keys 
with prospective peers as possible before joining a pool of synchronizing key servers.

The SKS reconciliation protocol is very efficient for synchronizing
large databases with relatively small differences. However, as these differences
become larger, the protocol creates queries and re-transmissions of
redundant key material and will spend a significant amount of CPU and I/O in
traversing the prefix trees to isolate these differences.

In extreme cases where the iterative descent of the prefix tree is very deep and time-consuming, SKS
reconciliation can time out and the keyservers will fail to ever get in
sync. They will just generate a lot of wasted effort and network traffic.

In Hockeypuck development and testing, I've used the sources listed at https://bitbucket.org/skskeyserver/sks-keyserver/wiki/KeydumpSources.

Hockeypuck & PostgreSQL Concerns
================================
The Hockeypuck database stores and indexes rich relationships between OpenPGP packets. The schema is optimized for queries: exploring the web of trust, searching user IDs, determining the validity of key material, and presenting reliable public key information in a nice UI or easy-to-consume HTTP API.

These indexes and constraints pose a problem for bulk loading of millions of keys in a short amount of time. Initial benchmarking during the development of Hockeypuck revealed that loading millions of public keys with all indexes and constraints enabled is too resource intensive to complete in any reasonable amount of time.

The bulk load process has been optimized, based on recommendations from the PostgreSQL documentation, `14.4. Populating a Database <http://www.postgresql.org/docs/current/interactive/populate.html>`_. You may be able to further improve performance from these recommendations by re-configuring your PostgreSQL database during pre-population.

Resource Estimates
==================

On a Rackspace cloud instance with 1xCPU & 1GB ram, Hockeypuck completed loading a full key dump of 3.4M keys in about 12-18 hours. This included the row de-duplication and constraint creation described below.

The uncompressed key dump files (about 3.4M keys) occupy 6.1G of disk space. The size of the Hockeypuck PostgreSQL database after loading them is 17.3G. The prefix tree grew to about 191M.

In general, expect about a factor of 3-4x disk space usage for a given amount of key material to load. Allow for additional peak disk usage during row de-duplication, as each table is copied and then the original dropped.

Loading
=======

Drop all database constraints
-----------------------------
Use the Hockeypuck database utility to drop all indexes and constraints::

  $ hockeypuck db --drop-constraints

Load the public key dump files
------------------------------
The key dump files contain public key material in RFC 4880 format. Load them into the database::

  $ hockeypuck load --config /path/to/hockeypuck.conf --path /path/to/sks-dump-\*.pgp

A couple of notes on loading.

Prefix Tree
~~~~~~~~~~~
If you don't specify a configuration file to 'hockeypuck load', the recon-ptree will be created in the current working directory. You may need to relocate this file and fix permissions after loading. The prefix tree must match the `configuration </configuration.html>`_.

If you're adding keys to an existing prefix tree database, use the '--ignore-dups' option, or the load will fail on prefix tree key collision.

Using a glob pattern in --path
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The --path option supports wildcard glob patterns, but you must escape these so that they are interpreted by hockeypuck, and not automatically expanded by the shell.

De-duplicate the PostgreSQL database & Create constraints
---------------------------------------------------------
Since the tables were loaded with constraints off, we need to make sure there are no duplicate rows before attempting to create them again::

  $ hockeypuck db --dedup --create-constraints

For each OpenPGP table, Hockeypuck will create an entirely new table with de-duplicated rows using a CREATE TABLE ... AS SELECT DISTINCT ... statement. Then the original table is dropped and the new de-duplicated table is renamed to the original. This has been found to be much faster than attempting to delete only the duplicate rows. However, it requires more peak disk space.

After the de-duplication step completes, the above command will create the indexes, primary key, unique and foreign-key constraints.
