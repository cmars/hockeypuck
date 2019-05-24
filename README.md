# Hockeypuck

Hockeypuck is an OpenPGP public keyserver. 

## Building

To locally build the hockeypuck binaries:

  make install-build-depends
  make

## Building a Release

In order to release a new version of hockeypuck:

  make dch
  git add debian/changelog
  git commit -m 'x.y.z release'
  git tag -s -u <keyid> -m 'x.y.z release' x.y.z
  git push --tags
  make deb-src
  dput <your ppa> ../hockeypuck\_x.y.z\_source.changes

Where `x.y.z` is the appropriate version number.
This will upload the debian source package to the Launchpad PPA for building.

## Vendored Dependencies

The dependencies for this project are managed via Go modules.
To update the dependencies run:

  cd src
  go get -u -m
  go mod vendor

After which you can ensure that the code continues to build and
that the tests still pass.
