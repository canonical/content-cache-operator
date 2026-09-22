---
myst:
  html_meta:
    "description lang=en": "A list of all components (charms) in the Content Cache operators project."
---

(reference_components)=

# Components

The Content Cache charm is deployed together with other charms to provide backend
configuration and, optionally, ingress in front of the cache.

## Content Cache

The [Content Cache](https://charmhub.io/content-cache) charm is the primary charm of the project.
It is a machine charm that manages an NGINX instance configured as a content cache. It exposes a
`cache-config` endpoint (interface: `content-cache-config`) that a backend-configuration charm
uses to describe which backends to cache, and a `certificates`/`receive-ca-cert` pair of
endpoints used for TLS.

## Content Cache Backends Config

The [Content Cache Backends Config](https://charmhub.io/content-cache-backends-config) charm is
a subordinate charm to the Content Cache charm. It provides the Content Cache charm with the
configuration required to expose a set of backend services behind the caching capabilities of
the Content Cache charm, directly over the `cache-config` endpoint.

## Ingress configurator

The [Ingress configurator](https://charmhub.io/ingress-configurator) charm is an alternative way
to configure Content Cache's backends. Like Content Cache Backends Config, it integrates with
Content Cache over the `cache-config` endpoint, translating its own configuration options
(backend addresses and ports, health check parameters, cache validity, TLS/hostname settings)
into the `content-cache-config` relation data that Content Cache consumes.

Deploying Ingress configurator together with the [HAProxy](https://charmhub.io/haproxy) charm
(over the `haproxy-route` interface) additionally provides an ingress layer in front of
Content Cache, adding hostname/path-based routing, TLS termination, DDoS protection, and other
features that Content Cache Backends Config does not offer on its own. See the
[Ingress configurator documentation](https://canonical.com/juju/docs/ingress-configurator-charm/latest/)
for its full configuration reference, and {ref}`Tutorial <tutorial_index>` for a walkthrough of
this deployment.

