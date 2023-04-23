# HAProxy shim deployment

You can insert HAProxy as a shim between an existing reverse proxy and keyserver,
keeping your existing SSL termination etc. in place and using HAProxy just for its rate limiting features.

    Existing proxy (e.g. Apache) [ -> HAProxy ] -> Keyserver

To do this, you can invoke a custom `docker-compose` config with the keyserver and certbot services disabled.

BEWARE that the followng is EXPERIMENTAL and provided as a guideline only. Your mileage WILL vary.

# Installation and configuration

A common use case is that of an Apache or Nginx reverse proxy installed on Linux.
In this case we can update the reverse proxy machine to install and reference the shim without touching the back end.

1. Install `docker` and `docker-compose` on the same machine as your existing proxy.

2. Clone the `pgpkeys-eu/hockeypuck` repo into a directory somewhere and check out the `haproxy-new` development branch, e.g.:

```
cd /usr/local
git clone https://github.com/pgpkeys-eu/hockeypuck
cd hockeypuck/contrib/docker-compose/standalone
git checkout haproxy-new
```

3. Populate the default site settings:

```
./mksite.bash
```

4. Edit the newly-created `.env` file:

* `FQDN` and `ALIAS_FQDNS` should be self-explanatory
* `KEYSERVER_HOST_PORT` should be uncommented and point to your existing keyserver HKP port (e.g. `keyserver-backend.example.com:11371`)
* `HAP_{HTTP,HTTPS,HKP}_HOST_PORT` should _all_ be uncommented and set to unused localhost ports e.g. `localhost:8080`
* `HAP_BEHIND_PROXY` should be uncommented and set to `true`

You can safely ignore the other settings.

Note that `KEYSERVER_HOST_PORT` is resolved inside the docker container, so `localhost:11371` will not work.
If you are running the keyserver on the same machine as the reverse proxy, you should use the docker host IP here,
e.g. `172.17.0.1:11371`, and make sure that your host iptables allows for incoming connections on the `docker0` interface.

At this point, haproxy is configured to talk to your keyserver back end, but to listen only on some unused localhost ports.
In this configuration it should not clash with anything you already have running on that machine.

## BEWARE

Docker-compose before v1.29 does not parse quoted values like a POSIX shell would.
This means that normally you should not quote values in `.env`,
as docker-compose's old behaviour is highly unintuitive.

The scripts in this directory try to compensate, and can parse *double* quotes around 
ALIAS_FQDNS, CLUSTER_FQDNS, and HKP_LOG_FORMAT values *only*,
as these values will normally contain whitespace and so most users will instinctively quote them anyway.

In all other cases, enclosing quotes MUST NOT be used.

# Testing and operation

To bring up HAProxy, make sure you are cd-ed into the `standalone` directory and incant:

```
docker-compose -f docker-compose-shim.yml up -d
```

It should start the following containers only:

* standalone_haproxy_1
* standalone_haproxy_internal_1
* standalone_haproxy_cache_1

To verify, incant

```
docker-compose -f docker-compose-shim.yml ps
```

to check that they are all running, and

```
docker-compose -f docker-compose-shim.yml logs -f <service>
```

to check the logs of each in turn for any obvious error messages.

(BTW yes, there are two `-f` options in the `logs` command; they mean different things depending on what order they come in the argument list)

To shut down, incant:

```
docker-compose -f docker-compose-shim.yml down
```

Once tested, you can start using haproxy by editing your front end config to point to HAProxy instead of directly to the keyserver.
For Apache, the following should be sufficent:

* Change the ProxyPass directives to point to the localhost:port that you configured in `HAP_HTTP_HOST_PORT` above (e.g. `localhost:8080`).
* Make sure that apache populates the `X-Forwarded-For` header (ProxyPass will do this by default), and has `ProxyPreserveHost on` (ProxyPass won’t do this by default).

If you don’t set X-Forwarded-For and ProxyPreserveHost correctly, HAProxy may mistakenly rate-limit your entire apache proxy, not just individual clients.
You can see the rate limiting in action by incanting:

```
docker-compose -f docker-compose-shim.yml logs -f haproxy
```

If all is working correctly, you should notice that “pgp-happy-eyeballs” is being tarpitted
(you will see `pgp-happy-eyeballs` on one log line, and `be_tarpit/<NOSRV>` on the next line) but other queries should be fine.

Andrew.
