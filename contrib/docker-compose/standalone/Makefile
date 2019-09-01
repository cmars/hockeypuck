
all: site.profile hockeypuck/etc/hockeypuck.conf nginx/conf.d/hockeypuck.conf

site.profile:
	./mksite.bash

hockeypuck/etc/hockeypuck.conf nginx/conf.d/hockeypuck.conf:
	./mkconfig.bash

clean:
	$(RM) hockeypuck/etc/hockeypuck.conf
	$(RM) nginx/conf.d/hockeypuck.conf
