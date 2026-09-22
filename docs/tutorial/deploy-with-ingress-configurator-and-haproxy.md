---
myst:
  html_meta:
    "description lang=en": "Deploy content-cache behind ingress-configurator and haproxy to get hostname-based routing, TLS termination, and other ingress features."
---

(tutorial_advanced_ingress)=

# Deploy content-cache with ingress-configurator and haproxy

The `content-cache` charm caches static content from a backend and serves it back to
clients. On its own, each backend it caches is reachable only through a dynamically
allocated TCP port (starting at `30000`) on the units it is deployed to. `content-cache` can
terminate TLS for that single hostname, but it has no hostname-based (SNI) routing across
multiple certificates, and no ingress-level protections.

This tutorial builds on the concepts of the basic content-cache tutorial and shows you how to
front `content-cache` with the [Ingress configurator](https://charmhub.io/ingress-configurator)
and [HAProxy](https://charmhub.io/haproxy) charms. Together, they let clients reach your cached
content through a normal hostname over HTTPS, and unlock features such as SNI-based hostname
routing, retries, and DDoS protections that `content-cache` does not provide by
itself.

Everything in this tutorial runs on a local [LXD](https://ubuntu.com/lxd) cloud, so you can
follow along without access to any Canonical-internal infrastructure.

## What you'll do

- Deploy `content-cache` and a minimal origin server.
- Deploy `ingress-configurator` and integrate it with `content-cache` to replace manual
  per-relation backend configuration.
- Deploy `haproxy` and integrate it with `ingress-configurator` to add hostname-based routing.
- Add TLS termination at the ingress with a self-signed certificate.

## What you'll need

You will need a workstation, e.g., a laptop, with AMD64 architecture. Your workstation should
have at least 4 CPU cores, 8 GB of RAM, and 50 GB of disk space.

```{tip}
You can use Multipass to create an isolated environment by running:

    multipass launch 24.04 --name charm-tutorial-vm --cpus 4 --memory 8G --disk 50G
```

This tutorial requires the following software to be installed on your workstation (either
locally or in the Multipass VM):

- Juju 3
- LXD
- `jq`

Use [Concierge](https://github.com/canonical/concierge) to set up Juju and `jq`:

```bash
sudo snap install --classic concierge
sudo concierge prepare -p machine
```

This first command installs Concierge, and the second command uses Concierge to install and
configure Juju and `jq`.

For this tutorial, Juju must be bootstrapped to a LXD controller. Concierge should complete
this step for you, and you can verify by checking for
`msg="Bootstrapped Juju" provider=lxd`
in the terminal output and by running `juju controllers`.

If Concierge did not perform the bootstrap, run:

```bash
juju bootstrap localhost tutorial-controller
```

To be able to work inside the Multipass VM, log in with the following command:

```bash
multipass shell charm-tutorial-vm
```

```{note}
If you're working locally, you don't need to do this step.
```

## Set up the environment

To manage resources effectively and to separate this tutorial's workload from your usual
work, create a new model in the LXD controller using the following command:

```bash
juju add-model content-cache-tutorial
```

## Deploy content-cache and a test origin

Deploy the Content Cache charm from the `1/edge` channel:

```bash
juju deploy content-cache --channel 1/edge
```

`content-cache` needs a backend to cache. Deploy a plain Ubuntu machine and install `nginx`,
which starts automatically and serves a default page, to stand in for a real origin:

```bash
juju deploy ubuntu --base ubuntu@24.04 origin
juju exec --unit origin/0 -- "sudo apt-get install -y nginx && echo '<h1>Hello from origin</h1>' | sudo tee /var/www/html/index.html"
```

Wait for the `origin` application to settle into `active`/`idle`. `content-cache` remains `blocked` until the `cache-config` relation is added in the next step:

```bash
juju status --watch 5s
```

Save the `origin` unit's IP address to an environment variable so you can reuse it in later
commands:

```bash
export ORIGIN_IP=$(juju status --format json | jq -r '.applications.origin.units."origin/0"."public-address"')
```

## Deploy ingress-configurator and connect it to content-cache

`ingress-configurator` translates a set of configuration options into the `cache-config`
relation data that `content-cache` consumes, replacing the need to configure the relation by
hand. Deploy it from the `latest/edge` channel:

```bash
juju deploy ingress-configurator --channel latest/edge
```

Point it at the origin server you deployed in the previous step:

```bash
juju config ingress-configurator \
  backend-addresses=$ORIGIN_IP \
  backend-ports=80 \
  backend-protocol=http
```

By default, `content-cache` only caches a response if the backend's own `Cache-Control` or
`Expires` headers say it's cacheable, and our test origin doesn't send either. Tell
`content-cache` to cache successful responses for an hour regardless, so you can see caching
in action later in this tutorial:

```bash
juju config ingress-configurator cache-proxy-cache-valid="200 1h"
```

Integrate `ingress-configurator` with `content-cache` over the `cache-config` endpoint:

```bash
juju integrate content-cache:cache-config ingress-configurator:cache-config
```

At this point both charms remain `blocked`: `ingress-configurator` won't publish backend
configuration to `content-cache` over `cache-config` until it also has a route relation,
which you'll add next by deploying `haproxy`.

## Deploy HAProxy and add hostname-based routing

So far, clients would reach the cache through `content-cache`'s dynamically allocated TCP
port, with no hostname-based routing and no protection beyond what `content-cache` itself
provides. Adding `haproxy` in front of `ingress-configurator` gives clients a normal HTTPS
hostname to connect to, and enables protocol- and DDoS-level protections by default
(connections with invalid, empty, or missing host headers are dropped, and connection/
keep-alive timeouts are enforced), without any extra configuration.

Deploy `haproxy` from the `2.8/stable` channel:

```bash
juju deploy haproxy --channel 2.8/stable
```

Integrate it with `ingress-configurator` over the `haproxy-route` endpoint:

```bash
juju integrate ingress-configurator:haproxy-route haproxy:haproxy-route
```

Let's give our deployment a hostname:

```bash
juju config ingress-configurator hostname=content-cache.local
```

`ingress-configurator` forwards this hostname to `haproxy`, which uses it both for request
routing and as the certificate common name once TLS is enabled.

`haproxy-route` requires HTTPS by default, and `haproxy` will not become `active` until it has a
TLS certificate. `content-cache` and `ingress-configurator` settle into `active`/`idle` once
`ingress-configurator` publishes the backend configuration, but `haproxy` stays `blocked` until
you complete the next step:

```bash
juju status --watch 5s
```

## Confirm content-cache is caching

Save the `content-cache` unit's IP address to an environment variable and curl it directly
on the port allocated for this relation (starting at `30000`):

```bash
export CONTENT_CACHE_IP=$(juju status --format json | jq -r '.applications."content-cache".units."content-cache/0"."public-address"')
curl http://$CONTENT_CACHE_IP:30000
```

You should see `Hello from origin`.

To confirm `content-cache` is actually caching the response rather than just forwarding it,
send the same request twice and inspect the cache log on the unit. `content-cache` logs a
`cache_status` field for every request, distinguishing a first-time `MISS` from a subsequent
`HIT`:

```bash
curl http://$CONTENT_CACHE_IP:30000 -o /dev/null -s
curl http://$CONTENT_CACHE_IP:30000 -o /dev/null -s
juju ssh content-cache/0 -- sudo tail -3 /var/log/nginx/content-cache_0/30000.cache.log
```

The first request populates the cache (`"cache_status": "MISS"`), and the second is served
straight from it (`"cache_status": "HIT"`), without `origin` being contacted again.

## Terminate TLS at the ingress

`haproxy` needs a TLS certificate before it can leave `blocked` and start routing traffic. In
production, use a real certificate authority such as [Let's Encrypt via the `lego`
charm](https://charmhub.io/lego). For this tutorial, deploy `self-signed-certificates` and
integrate it with `haproxy`:

```bash
juju deploy self-signed-certificates --channel 1/stable
juju integrate haproxy:certificates self-signed-certificates:certificates
```

```{warning}
`self-signed-certificates` is only suitable for local testing. Never use it in production.
```

Once the relation settles, `haproxy` requests and receives a certificate for
`content-cache.local` (the hostname you configured earlier). Wait for `haproxy` and
`self-signed-certificates` to both reach `active`/`idle` before continuing — fetching the
certificate too early returns an empty or incomplete one:

```bash
juju status --watch 5s
```

You should see all five applications `active`/`idle`:

```{terminal}
juju status

Model                   Controller     Cloud/Region         Version  SLA          Timestamp
content-cache-tutorial  concierge-lxd  localhost/localhost  3.6.28   unsupported  08:52:29-04:00

App                       Version  Status  Scale  Charm                     Channel        Rev  Exposed  Message
content-cache                      active      1  content-cache             1/edge         534  no
haproxy                            active      1  haproxy                   2.8/stable     557  no       1/1 valid relations
ingress-configurator               active      1  ingress-configurator      latest/edge    107  no       Ready
origin                    24.04    active      1  ubuntu                    latest/stable   79  no
self-signed-certificates           active      1  self-signed-certificates  1/stable       586  no

Unit                         Workload  Agent  Machine  Public address  Ports       Message
content-cache/0*             active    idle   0        10.48.188.3     30000/tcp
haproxy/0*                   active    idle   3        10.48.188.161   80,443/tcp  1/1 valid relations
ingress-configurator/0*      active    idle   2        10.48.188.138               Ready
origin/0*                    active    idle   1        10.48.188.164
self-signed-certificates/0*  active    idle   4        10.48.188.150

Machine  State    Address        Inst id        Base          AZ                 Message
0        started  10.48.188.3    juju-2724a6-0  ubuntu@24.04  charm-tutorial-vm  Running
1        started  10.48.188.164  juju-2724a6-1  ubuntu@24.04  charm-tutorial-vm  Running
2        started  10.48.188.138  juju-2724a6-2  ubuntu@24.04  charm-tutorial-vm  Running
3        started  10.48.188.161  juju-2724a6-3  ubuntu@24.04  charm-tutorial-vm  Running
4        started  10.48.188.150  juju-2724a6-4  ubuntu@24.04  charm-tutorial-vm  Running
```

Fetch the issued certificate's CA so you can verify it with `curl`:

```bash
juju run haproxy/0 get-certificate hostname=content-cache.local --format=json \
  | jq -r '.[].results.ca' > ca.pem
```

Find the `haproxy` unit's IP address, save it to an environment variable, and test the whole
path end to end, resolving the hostname to that address:

```bash
export HAPROXY_IP=$(juju status --format json | jq -r '.applications.haproxy.units."haproxy/0"."public-address"')
curl --resolve content-cache.local:443:$HAPROXY_IP --cacert ca.pem https://content-cache.local/
```

You should see `Hello from origin` again — but this time served over HTTPS, on the standard
port, addressed by a hostname you chose, with no need to know or track the port that
`content-cache` allocated internally.

Compared to relating `ingress-configurator` directly to `content-cache`, adding `haproxy` in
front unlocks:

- **Hostname and path-based routing**: reach the cache by name over the standard HTTPS
  port.
- **TLS termination**: `haproxy` presents a real client-facing certificate, obtained
  automatically through the `certificates` relation.

## Next steps

Now that you have a working deployment with hostname-based routing, DDoS protections, and TLS
termination, you can:

- Explore the [ingress-configurator](https://charmhub.io/ingress-configurator/configurations)
  and [haproxy](https://charmhub.io/haproxy/configurations) configuration references for
  additional controls such as health check tuning and retries.
- Use a real certificate authority in production by integrating `haproxy` with the
  [`lego`](https://charmhub.io/lego) charm instead of `self-signed-certificates`.
- Read the content-cache {ref}`how-to guides <how_to_index>` for day-2 operations, such as
  enabling COS observability or connecting to HTTPS backends.

## Clean up

Remove the applications you deployed in this tutorial:

```bash
juju remove-application content-cache ingress-configurator haproxy self-signed-certificates origin
```
