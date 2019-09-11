# Standalone docker-compose deployment

The docker-compose and supporting scripts in this directory are useful for
running a full Hockeypuck deployment on a single machine.

Obviously, this will not be a highly-available deployment, but it can be useful
for a low-cost, low-maintenance deployment.

# Supported platforms

Tested on official Ubuntu 18.04 cloud images, with dependencies installed using
`./setup.bash`.

Other platforms may work but may require some customization.

# Installation

0. (Optional) Register a DNS name for your server's public IP address.
1. Configure your ingress firewall to allow ports: 80, 443, 11370, 11371
2. Create a `site.profile` by running `./mksite.bash`.
3. Customize the settings in `site.profile` to your liking.
   (Optional) If you're using DNS & TLS, make sure FQDN and EMAIL are correct;
   they're used for Let's Encrypt.
4. Generate hockeypuck and nginx configuration from your site settings with
   `./mkconfig.bash`.
5. (Optional) Set up TLS with `./init-letsencrypt.bash`. Answer the prompts as
   needed. If you want to test LE first with staging before getting a real
   cert, change `staging=0` to `staging=1` in this script.
6. `docker-compose up -d` and your Hockeypuck should be live.

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

