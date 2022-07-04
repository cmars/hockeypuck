# Standalone docker-compose deployment

The docker-compose and supporting scripts in this directory are useful for
running a full Hockeypuck deployment on a single machine.

Obviously, this will not be a highly-available deployment, but it can be useful
for a low-cost, low-maintenance deployment.

NB: all the below assume that you have `cd`-ed into this directory first.

# Supported platforms

Tested on Ubuntu 20.04 and Debian 11 (bullseye), with dependencies installed using `./setup.bash`.

Other platforms may work but will require some customization.
At minimum, docker and docker-compose (v1.5 or later) must be installed in advance.

# Installation

* (Optional) Register a DNS name for your server's public IP address.
* Configure your ingress firewall to allow ports: 80, 443, 11370, 11371
* Create a `.env` file by running `./mksite.bash`.
* Customize the settings in `.env` to your liking.
   Set EMAIL and FINGERPRINT to the contact email and associated PGP fingerprint of the site admin.
   Set FQDN and (optionally) ALIAS_FQDNS to the primary (and other) DNS name(s) of your server.
   (Optional) Set ACME_SERVER to your internal CA if not using Let's Encrypt.
* Generate hockeypuck and nginx configuration from your site settings with
   `./mkconfig.bash`.
* Build hockeypuck by incanting `docker-compose build`.
* (Optional) Set up TLS with `./init-letsencrypt.bash`. Answer the prompts as
   needed. If you want to test LE first with staging before getting a real
   cert, set the environment variable `CERTBOT_STAGING=1`.
* Download a keydump by running `./sync-sks-dump.bash`.
* Incant `docker-compose up -d` to start Hockeypuck and all dependencies.
   It will take several hours (or days) to load the keydump on first invocation.
   You can keep track of progress by running `docker logs -f standalone_hockeypuck_1`.
* Once you are sure Hockeypuck has loaded all keys, you can run
   `./clean-sks-dump.bash` to remove the dump files and recover disk space.

# Configuration

* Hockeypuck configuration: `hockeypuck/etc/hockeypuck.conf`
* NGINX configuration: `nginx/conf.d/hockeypuck.conf`
* Prometheus configuration: `prometheus/etc/prometheus.yml`

To reload services after changing the configuration, incant `docker-compose restart`.

# Upgrading

To upgrade hockeypuck to the latest commit, incant:

```
git pull
docker-compose build
docker-compose down
docker-compose up -d
```

This will leave behind stale intermediate images, which may be quite large.
To clean them up, incant `docker images -f 'label=io.hockeypuck.temp=true' -q | xargs docker rmi`.

# Operation

## Monitoring

By default the prometheus monitoring console is not accessible from external IP addresses.
To change this, edit `nginx/conf.d/hockeypuck.conf` as appropriate.
Once done, browse to `https://FQDN/monitoring/prometheus` to access the monitoring console.

## Obtaining a new keyserver dump

Use `./sync-sks-dump.bash` to fetch a recent keyserver dump from a public location.
This script may need to be edited depending on the availability of dump servers.

## Loading a keyserver dump

Use `./load-sks-dump.bash` to load the keyserver dump (make sure that Hockeypuck is not running).
This can be I/O intensive on PostgreSQL and may take several hours (or days) to complete.

## Removing stale dumpfiles

Use `./clean-sks-dump.bash` to remove stale dump files from the import volume and save space.
This will preserve the timestamp file that indicates a keydump has been loaded.
To start from scratch instead, destroy the import volume using `docker volume rm pgp_import`.

## Blacklisting and deleting keys

To blacklist a key, add its full fingerprint (without any `0x`) to the `hockeypuck.openpgp.blacklist` array in `hockeypuck/etc/hockeypuck.conf`, e.g.:

```
[hockeypuck.openpgp]
blacklist=[
   "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
]
```

Note that blacklisting will only prevent updates to this key via e.g. gossip.
It WILL NOT delete any existing keys in the postgres database.
To delete a key or keys from the database, use the `delete-keys.bash` script in this directory:

```
./delete-keys.bash DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
```

You can delete multiple keys by providing multiple arguments.

In case of accidental deletion, you will need to remove the key from the blacklist and then rebuild your PTtree (see below).

# Debugging

## PTree corruption

Hockeypuck can sometimes suffer from PTree corruption.
Signs of corruption include:

* A key count that diverges significantly from its direct peers
* Key searches that produce stale output
* Missing keys

If any of the above persist for several days, rebuilding the PTree may help.
First, stop the running hockeypuck using `docker-compose down`.
Then run `./ptree-rebuild.bash`, and finally `docker-compose up -d`.
