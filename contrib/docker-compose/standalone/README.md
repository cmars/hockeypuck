# Standalone docker-compose deployment

The docker-compose and supporting scripts in this directory are useful for
running a full Hockeypuck deployment on a single machine.

Obviously, this will not be a highly-available deployment, but it can be useful
for a low-cost, low-maintenance deployment.

# Supported platforms

Tested on official Ubuntu 18.04 cloud images, with dependencies installed using
`./setup.bash`.

Other platforms may work but may require some customization.

# Building

* `cd` to the base directory of this repository
* Run `docker build .` - it should return e.g. "Successfully built DEADBEEF1234"
* Tag the build: `docker tag DEADBEEF1234 hockeypuck/hockeypuck:RELEASE`
  (replacing `DEADBEEF1234` with the hash emitted by `docker build .`,
  and `RELEASE` as appropriate, cf `../../../debian/changelog` and/or `./mksite.bash`)
* Now `cd` back to this directory before continuing below

# Installation

* (Optional) Register a DNS name for your server's public IP address.
* Configure your ingress firewall to allow ports: 80, 443, 11370, 11371
* Create a `.env` file by running `./mksite.bash`.
* Customize the settings in `.env` to your liking.
   Make sure that `RELEASE` matches the docker tag you created above.
   (Optional) If you're using DNS & TLS, make sure FQDN and EMAIL are correct;
   they're used for Let's Encrypt.
* Generate hockeypuck and nginx configuration from your site settings with
   `./mkconfig.bash`.
* (Optional) Set up TLS with `./init-letsencrypt.bash`. Answer the prompts as
   needed. If you want to test LE first with staging before getting a real
   cert, change `staging=0` to `staging=1` in this script.
* Download a keydump by running `./sync-sks-dump.bash`.
* `docker-compose up -d` and your Hockeypuck should be live.

# Configuration

* Hockeypuck configuration: `hockeypuck/etc/hockeypuck.conf`
* NGINX configuration: `nginx/conf.d/nginx.conf`
* Prometheus configuration: `prometheus/etc/prometheus.yml`

# Operation

## Monitoring

Browse to /monitoring/prometheus to access prometheus. If you don't want this
to be public, edit `nginx/conf.d/hockeypuck.conf` to your liking.

## Obtaining a keyserver dump

Use `sync-sks-dump.bash` to fetch a full keyserver dump from a public location.
This may need to be changed depending on availability.

## Loading a keyserver dump

Use `load-sks-dump.bash` to load the keyserver dump into Hockeypuck. This can
be I/O intensive on PostgreSQL and may take several days to complete when
first loading an empty database.

