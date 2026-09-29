---
myst:
  html_meta:
    "description lang=en": "Reference for the intended deployment architecture of the Content Cache charm: required components, supported relations, and how they combine to support common use cases."
---

(reference_deployment_architecture)=

# Intended deployment architecture

The Content Cache charm is deliberately narrow in scope: it manages an nginx instance that
caches responses from a set of backends. It does not know how to discover backends,
route by hostname or path, or terminate client-facing TLS on its own. Those responsibilities
are delegated to other charms over relations. This page describes the components required
for a working deployment, the relations the charm supports, and how combining them enables
or restricts specific use cases.

## Can Content Cache be deployed on its own?

No. Content Cache has no charm configuration options of its own — every behavior (which
backends to proxy to, health check parameters, cache TTLs) is supplied entirely through the
`cache-config` relation. Deployed alone, with no related charm providing that relation, the
unit has no backends configured: nginx serves no cache locations, and the unit sits in
`blocked` status, waiting for a config-providing charm to be integrated.

## Required components

A working deployment needs at least two charms:

1. **Content Cache** — this charm. Runs nginx, terminates the caching layer, and (optionally)
   terminates incoming TLS.
2. **A backend-configuration charm**, providing the `cache-config` relation. Exactly one of:
   - [**Content Cache Backends Config**](https://charmhub.io/content-cache-backends-config) — a
     subordinate charm deployed onto the Content Cache unit. It provides a direct, minimal way
     to describe a set of backends (addresses, health check parameters, cache validity) with no
     routing or ingress features.
   - [**Ingress configurator**](https://charmhub.io/ingress-configurator) — a principal charm
     that translates its own configuration into the same `cache-config` relation data. On its
     own it provides the same backend-configuration role as Content Cache Backends Config, but
     it is also designed to be paired with [**HAProxy**](https://charmhub.io/haproxy) (over the
     `haproxy-route` interface) to add an ingress layer in front of Content Cache: hostname/path
     routing, TLS termination, DDoS protection, and health-check-based retries.

Everything else described below is optional and layers additional capability onto this
minimal pair.

## Supported relations

| Relation endpoint | Interface | Direction | Required? | Purpose |
|---|---|---|---|---|
| `cache-config` | `content-cache-config` | provides | Yes | Backend addresses and per-backend cache/health-check settings. Without this relation the charm has nothing to cache. |
| `certificates` | `tls-certificates` | requires | Optional | Terminate TLS for incoming connections directly at Content Cache (see {ref}`use cases <reference_deployment_architecture_use_cases>` below). |
| `receive-ca-cert` | `certificate_transfer` | requires | Conditionally | Trust a CA so nginx can verify backend certificates. Required only if any configured backend uses an `https://` URL; ignored entirely for HTTP-only backends. |
| `cos-agent` | `cos_agent` | provides | Optional | Ship metrics/logs to a Canonical Observability Stack (COS) via `grafana-agent` or an equivalent principal charm. |
| `content-cache-peers` | `content-cache-peers` | peers | Automatic | Coordinates per-relation port allocation across all units of the same Content Cache application. Not user-configured. |

(reference_deployment_architecture_use_cases)=

## How relations combine to support use cases

### Direct backend caching (no ingress)

```
Content Cache Backends Config (subordinate) — cache-config — Content Cache
```

The simplest supported deployment. Content Cache Backends Config is deployed as a subordinate
directly onto the Content Cache unit and describes one set of backends. There is no
hostname/path-based routing: each `cache-config` relation is served on its own dedicated port
(see {ref}`explanation_charm_design`), and callers reach it directly at
`http://<content-cache-unit-ip>:<port>`.

This pattern suits deployments with a small, fixed number of backend groups where clients (or
an existing load balancer) can address content-cache units and ports directly, and where
routing decisions do not need to change dynamically.

### Ingress-fronted caching

```
Backend/origin — Ingress configurator — cache-config — Content Cache
                       |
                  haproxy-route
                       |
                    HAProxy
```

Deploying Ingress configurator instead of Content Cache Backends Config unlocks pairing with
HAProxy. HAProxy sits in front of the Content Cache units and adds:

- Hostname- and path-based routing to the correct `cache-config` relation/port
- TLS termination for client-facing traffic
- Load balancing across multiple Content Cache units serving the same relation
- DDoS protection and configurable retry behavior

This pattern suits deployments that need a single public entry point in front of multiple
backends or content-cache relations, or that need TLS termination without configuring
certificates on Content Cache itself. See the
{ref}`tutorial <tutorial_advanced_ingress>` for a full walkthrough of this deployment.

### HTTPS to backends

Independent of which backend-configuration charm is used, if any backend is addressed with an
`https://` URL, Content Cache must also receive a trusted CA via `receive-ca-cert` (typically
from the same certificate provider used elsewhere in the deployment, such as
`self-signed-certificates` or `lego`). Without it, the charm enters `WaitingStatus` rather than
proxying to a backend it cannot verify. See {ref}`how_to_enable_https`.

### TLS termination directly at Content Cache

The `certificates` relation lets Content Cache present its own TLS certificate and listen with
`ssl` on its allocated port, independent of whether an ingress is present. This is most useful
in the ingress-fronted pattern above as a second TLS hop between HAProxy and Content Cache
(so traffic is encrypted for its entire path, not just from the client to HAProxy), but it can
also be used without HAProxy, in front of a direct Content Cache Backends Config deployment, if
callers need to reach Content Cache over HTTPS directly. See {ref}`how_to_enable_https`.

### Observability

The `cos-agent` relation is additive to any of the patterns above: integrating a `grafana-agent`
(or equivalent) principal charm collects nginx metrics and logs into COS without changing how
backends are configured. See {ref}`how_to_enable_cos`.

## What Content Cache does not do

To keep the intended deployment boundaries clear, Content Cache does not:

- Discover backends on its own — every backend must be described over `cache-config` by a
  related charm.
- Route by hostname or path — that requires Ingress configurator paired with HAProxy.
- Cache personalized or session-dependent content — see
  {ref}`explanation_charm_design` for the static-only caching assumption.
