PROJECTPATH = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
export GOPATH := $(PROJECTPATH)
export GOCACHE := $(GOPATH)/.gocache
export GOROOT :=
export PATH := /usr/lib/go-1.12/bin:$(PATH)

project = hockeypuck

prefix = /usr
statedir = /var/lib/$(project)

commands = \
	hockeypuck \
	hockeypuck-dump \
	hockeypuck-load \
	hockeypuck-pbuild

all: lint test build

build:

clean: clean-go

clean-go:
	-chmod -R u+rwX pkg
	rm -rf $(PROJECTPATH)/.gocache
	rm -rf $(PROJECTPATH)/bin
	rm -rf $(PROJECTPATH)/pkg

dch:
	gbp dch --debian-tag='%(version)s' -D bionic --git-log --first-parent

deb-src:
	debuild -S -sa -I

install:
	mkdir -p -m 0755 $(DESTDIR)/$(prefix)/bin
	cp -a bin/hockeypuck* $(DESTDIR)/$(prefix)/bin
	mkdir -p -m 0755 $(DESTDIR)/etc/hockeypuck
	cp -a contrib/config/hockeypuck.conf* $(DESTDIR)/etc/hockeypuck
	mkdir -p -m 0755 $(DESTDIR)$(statedir)/templates
	cp -a contrib/templates/*.tmpl $(DESTDIR)$(statedir)/templates
	mkdir -p -m 0755 $(DESTDIR)$(statedir)/www
	cp -a contrib/webroot/* $(DESTDIR)$(statedir)/www

install-build-depends:
	sudo apt-add-repository -y ppa:canonical-sysadmins/golang
	sudo apt install -y \
	    debhelper \
		dh-systemd \
	    git-buildpackage \
	    golang-1.12  # Requires ppa:canonical-sysadmins/golang

lint: lint-go

lint-go:
	go fmt $(project)/...
	go vet $(project)/...

test: test-go

test-go:
	go test $(project)/...

test-mongodb:
	go test $(project)/mgohkp/... -mongodb-integration

test-postgresql:
	go test $(project)/pghkp/... -postgresql-integration
	go test $(project)/pgtest/... -postgresql-integration

#
# Generate targets to build Go commands.
#
define make-go-cmd-target
	$(eval cmd_name := $1)
	$(eval cmd_package := $(project)/server/cmd/$(cmd_name))
	$(eval cmd_target := $(cmd_name))

$(cmd_target):
	go install $(cmd_package)

build: $(cmd_target)

endef

$(foreach command,$(commands),$(eval $(call make-go-cmd-target,$(command))))

#
# Generate targets to test Go packages.
#
define make-go-pkg-target
	$(eval pkg_path := $1)
	$(eval pkg_target := $(subst /,-,$(pkg_path)))

coverage-$(pkg_target):
	go test $(pkg_path) -coverprofile=cover.out
	go tool cover -html=cover.out
	rm cover.out

coverage: coverage-$(pkg_target)

test-$(pkg_target):
	go test $(pkg_path)

test-go: test-$(pkg_target)

endef

$(foreach package,$(packages),$(eval $(call make-go-pkg-target,$(package))))
