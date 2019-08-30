# Canonical IS Hockeypuck

This repo contains a version of the hockeypuck OpenPGP key server.

The Launchpad project can be found
[here](https://launchpad.net/canonical-is-hockeypuck).

The code for this repository can be cloned with:

    git clone git+ssh://git.launchpad.net/canonical-is-hockeypuck

## Building

To locally build the hockeypuck binaries:

    make install-build-depends
    make

## Building a Snap

If it's installed, remove the snapcraft Ubuntu package:

    sudo apt remove snapcraft

Install snapcraft from the Snap store:

    snap install snapcraft

Confirm that you're using a recent enough version of snapcraft:

    $ which snapcraft
    /snap/bin/snapcraft
    $ snapcraft version
    snapcraft, version 3.7.2
    $ _

Now you can build the snap:

    snapcraft snap

snapcraft defaults to building in a multipass VM.  If you're already
in a throwaway environment, you can build the snap as follows instead:

    SNAPCRAFT_BUILD_ENVIRONMENT=host snapcraft snap

## Building a Release

In order to release a new version of hockeypuck:

    make dch
    git add debian/changelog
    git commit -m 'x.y.z release'
    git tag -s -u <keyid> -m 'x.y.z release' x.y.z
    git push --tags
    make deb-src
    dput ppa:canonical-sysadmins/hockeypuck-devel ../hockeypuck\_x.y.z\_source.changes

Where `x.y.z` is the appropriate version number.
This will upload the debian source package to the
[hockeypuck devel PPA](https://launchpad.net/~canonical-sysadmins/+archive/ubuntu/hockeypuck-devel)
for building.
Once built the packages will be available for testing and promotion.

## Subtrees

The hockeypuck source code has been pulled in as subtrees.
These were added with the following commands:

    git subtree add --prefix=src/hockeypuck/conflux https://github.com/hockeypuck/conflux master --squash
    git subtree add --prefix=src/hockeypuck/hkp https://github.com/hockeypuck/hkp master --squash
    git subtree add --prefix=src/hockeypuck/logrus https://github.com/hockeypuck/logrus master --squash
    git subtree add --prefix=src/hockeypuck/mgohkp https://github.com/hockeypuck/mgohkp master --squash
    git subtree add --prefix=src/hockeypuck/openpgp https://github.com/hockeypuck/openpgp master --squash
    git subtree add --prefix=src/hockeypuck/pghkp https://github.com/hockeypuck/pghkp master --squash
    git subtree add --prefix=src/hockeypuck/pgtest https://github.com/hockeypuck/pgtest master --squash
    git subtree add --prefix=src/hockeypuck/server https://github.com/hockeypuck/server master --squash
    git subtree add --prefix=src/hockeypuck/testing https://github.com/hockeypuck/testing master --squash

To update:

    git subtree pull --prefix=src/hockeypuck/conflux https://github.com/hockeypuck/conflux master --squash
    git subtree pull --prefix=src/hockeypuck/hkp https://github.com/hockeypuck/hkp master --squash
    git subtree pull --prefix=src/hockeypuck/logrus https://github.com/hockeypuck/logrus master --squash
    git subtree pull --prefix=src/hockeypuck/mgohkp https://github.com/hockeypuck/mgohkp master --squash
    git subtree pull --prefix=src/hockeypuck/openpgp https://github.com/hockeypuck/openpgp master --squash
    git subtree pull --prefix=src/hockeypuck/pghkp https://github.com/hockeypuck/pghkp master --squash
    git subtree pull --prefix=src/hockeypuck/pgtest https://github.com/hockeypuck/pgtest master --squash
    git subtree pull --prefix=src/hockeypuck/server https://github.com/hockeypuck/server master --squash
    git subtree pull --prefix=src/hockeypuck/testing https://github.com/hockeypuck/testing master --squash

## Vendored Dependencies

The dependencies for this project are managed via Go modules.
To update the dependencies run:

    cd src
    go get -u -m
    go mod vendor

After which you can ensure that the code continues to build and
that the tests still pass.
