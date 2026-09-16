---
myst:
  html_meta:
    "description lang=en": "Deploy content-cache behind ingress-configurator and haproxy to get hostname-based routing, TLS termination, and other ingress features."
---

(tutorial_advanced_ingress)=

# Deploy content-cache with ingress-configurator and haproxy

The `content-cache` charm caches static content from a backend and serves it back to
clients. On its own, each backend it caches is reachable only through a dynamically
allocated TCP port (starting at `30000`) on the units it is deployed to. There is no
hostname-based routing, TLS termination for incoming traffic, or ingress-level protections.

This tutorial builds on the concepts of the basic content-cache tutorial and shows you how to
front `content-cache` with the [Ingress configurator](https://charmhub.io/ingress-configurator)
and [HAProxy](https://charmhub.io/haproxy) charms. Together, they let clients reach your cached
content through a normal hostname over HTTPS, and unlock features such as TLS termination,
retries, and DDoS protections that `content-cache` does not provide by
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

- A workstation, for example a laptop, with amd64 architecture.
- Juju 3 installed and bootstrapped to a LXD controller. You can set this up using a Multipass
  VM as outlined in {ref}`Set up / Tear down your test environment <juju:set-things-up>`.

## 1. Deploy content-cache and a test origin

Bootstrap or switch to a model, then deploy the Content Cache charm from the `1/edge` channel:

```bash
juju deploy content-cache --channel 1/edge
```

`content-cache` needs a backend to cache. Deploy a plain Ubuntu machine and start a minimal
HTTP server on it to stand in for a real origin:

```bash
juju deploy ubuntu --base ubuntu@24.04 origin
juju exec --unit origin/0 -- "echo '<h1>Hello from origin</h1>' | sudo tee /var/www/html/index.html && sudo apt-get install -y python3 && cd /var/www/html && (nohup sudo python3 -m http.server 80 >/tmp/http-server.log 2>&1 &)"
```

Wait for the `origin` application to settle into `active`/`idle`. `content-cache` remains `blocked` until the `cache-config` relation is added in step 2:

```bash
juju status --watch 5s
```

Note the IP address of the `origin` unit reported by `juju status` as you'll need it in the
next step.


## 2. Deploy ingress-configurator and connect it to content-cache

`ingress-configurator` translates a set of configuration options into the `cache-config`
relation data that `content-cache` consumes, replacing the need to configure the relation by
hand. Deploy it from the `latest/edge` channel:

```bash
juju deploy ingress-configurator --channel latest/edge
```

Point it at the origin server you deployed in step 1 (replace `<origin-ip>` with the address
you noted earlier):

```bash
juju config ingress-configurator \
  backend-addresses=<origin-ip> \
  backend-ports=80 \
  backend-protocol=http
```

Integrate `ingress-configurator` with `content-cache` over the `cache-config` endpoint:

```bash
juju integrate content-cache:cache-config ingress-configurator:cache-config
```

Once both charms settle, `content-cache` allocates a port for this relation (starting at
`30000`) and starts caching the origin. You can confirm this works by curling the
`content-cache` unit directly on that port:

```bash
curl http://<content-cache-unit-ip>:30000
```

You should see `Hello from origin`. At this point you have a working deployment equivalent to
what you'd get with the simpler `content-cache-backends-config` subordinate charm, but using
`ingress-configurator` so you can add `haproxy` next.

## 3. Deploy haproxy and add hostname-based routing

Deploy `haproxy` from the `2.8/stable` channel:

```bash
juju deploy haproxy --channel 2.8/stable
```

Integrate it with `ingress-configurator` over the `haproxy-route` endpoint:

```bash
juju integrate ingress-configurator:haproxy-route haproxy:haproxy-route
```

Give your deployment a hostname. `ingress-configurator` forwards this hostname to `haproxy`,
which uses it both for request routing and as the certificate common name once TLS is
enabled:

```bash
juju config ingress-configurator hostname=content-cache.local
```

`haproxy-route` is HTTPS-only by default, so you need a certificate before traffic will be
routed (see the next step). If you want to test plain HTTP first, temporarily set
`allow-http=true`; this is **not** recommended for anything beyond local testing:

```bash
juju config ingress-configurator allow-http=true
```

## 4. Terminate TLS at the ingress

In production, use a real certificate authority such as [Let's Encrypt via the `lego`
charm](https://charmhub.io/lego). For this tutorial, deploy `self-signed-certificates` so
everything works:

```bash
juju deploy self-signed-certificates --channel 1/stable
juju integrate haproxy:certificates self-signed-certificates:certificates
```

Once the relation settles, `haproxy` requests and receives a certificate for
`content-cache.local` (the hostname you configured in step 3). You can drop the `allow-http`
override now, since HTTPS is available:

```bash
juju config ingress-configurator allow-http=false
```

Fetch the issued certificate's CA so you can verify it with `curl`:

```bash
juju run haproxy/0 get-certificate hostname=content-cache.local --format=json \
  | jq -r '.[].results.ca' > ca.pem
```

Find the `haproxy` unit's IP address with `juju status`, then test the whole path end to end,
resolving the hostname to that address:

```bash
curl --resolve content-cache.local:443:<haproxy-unit-ip> --cacert ca.pem https://content-cache.local/
```

You should see `Hello from origin` again — but this time served over HTTPS, on the standard
port, addressed by a hostname you chose, with no need to know or track the port that
`content-cache` allocated internally.

## What you gained

Compared to relating `ingress-configurator` directly to `content-cache` (step 2), adding
`haproxy` in front unlocks:

- **Hostname and path-based routing** — reach the cache by name over the standard HTTPS
  port, and route different `paths`/`additional-hostnames` to different backends
  (see the `paths`, `hostname`, and `additional-hostnames` options).
- **TLS termination** — `haproxy` presents a real client-facing certificate, obtained
  automatically through the `certificates` relation, instead of leaving TLS entirely to an
  upstream you'd otherwise have to run yourself.
- **DDoS and protocol protections** — enabled by default through haproxy's
  `ddos-protection` option (drops connections with invalid, empty, or missing host headers,
  applies connection/keep-alive timeouts).
- **HSTS** — set `juju config haproxy enable-hsts=true` to send
  `Strict-Transport-Security` for hostnames routed without `allow-http`.
- **Load balancing and retries across multiple content-cache units** — `load-balancing-algorithm`,
  `retry-count`, and `retry-redispatch` on `ingress-configurator` let you scale `content-cache`
  horizontally (`juju add-unit content-cache`) behind a single hostname.
- **Tunable health checks** — `health-check-interval`, `health-check-rise`, and
  `health-check-fall` on `ingress-configurator` control how haproxy decides a `content-cache`
- **Hostname and path-based routing**: reach the cache by name over the standard HTTPS
  port.
- **TLS termination**: `haproxy` presents a real client-facing certificate, obtained
  automatically through the `certificates` relation.
- **DDoS and protocol protections**: enabled by default through haproxy's
  `ddos-protection` option (drops connections with invalid, empty, or missing host headers,
  applies connection/keep-alive timeouts).

See the [ingress-configurator](https://charmhub.io/ingress-configurator/configurations) and
[haproxy](https://charmhub.io/haproxy/configurations) configuration references for the full
list of options.

## Clean up

Remove the applications you deployed in this tutorial:

```bash
juju remove-application content-cache ingress-configurator haproxy self-signed-certificates origin
```
