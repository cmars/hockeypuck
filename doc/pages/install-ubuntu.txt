.. title: Install on Ubuntu Server
.. slug: install-ubuntu
.. date: 2013/09/30 21:45:00
.. tags: 
.. link: 
.. description: 


Ubuntu 14.04
============
Hockeypuck is in trusty universe. No need to add the PPA, unless you want to install newer packages for some reason.

Ubuntu 12.04
============

Add the Hockeypuck project package repository
---------------------------------------------

PPA prerequisites
~~~~~~~~~~~~~~~~~
In order to add PPA repositories, you'll need to make sure you have the necessary pacakges installed to manage PPAs on your server. These may already be installed on a desktop Ubuntu distribution, but may not be present on a minimal server image.::

  $ sudo apt-get install python-software-properties

Add the stable Hockeypuck repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

  $ sudo apt-add-repository ppa:hockeypuck/ppa

Update the package list
=======================
::

  $ sudo apt-get update

Install PostgreSQL
==================
If you want to run the PostgreSQL database on the same server as Hockeypuck, install it now::

  $ sudo apt-get install postgresql

Otherwise, skip and install hockeypuck. You'll need to `configure </configuration.html>`_ your Hockeypuck instance to connect to your PostgreSQL database.

Install Hockeypuck
==================
::

  $ sudo apt-get install hockeypuck

Next Steps
==========
`Configure </configuration.html>`_ your Hockeypuck instance.
