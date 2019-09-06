# Consolidation of Hockeypuck project repositories

Sources have been aggregated from several Hockeypuck Github projects here as subtrees.
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

The upstream Github projects have been archived. Any new development on Hockeypuck should be proposed here.
