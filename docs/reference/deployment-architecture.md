---
myst:
  html_meta:
    "description lang=en": "Reference for the intended deployment architecture of the Content Cache charm: required components, supported relations, and how they combine to support common use cases."
---

(reference_deployment_architecture)=

# Intended deployment architecture

The Content Cache charm manages an nginx instance that
caches responses from a set of backends. It does not know how to discover backends,
route by hostname or path, or terminate client-facing TLS on its own. Those responsibilities
are delegated to other charms over relations. 

**Content Cache cannot be deployed by itself.** 
It has no charm configuration options of its own — every behavior (which
backends to proxy to, health check parameters, cache TTLs) is supplied entirely through the
`cache-config` relation. Deployed alone, with no related charm providing that relation, the
unit has no backends configured: nginx serves no cache locations, and the unit sits in
`blocked` status, waiting for a config-providing charm to be integrated.

This page describes the components required
for a working deployment, the relations the charm supports, and how combining them enables
or restricts specific use cases.

## Required components

A working deployment needs at least two charms:

1. **Content Cache** — this charm. Runs nginx and performs the actual caching (cache hit/miss
   decisions, disk and RAM storage). Optionally terminates incoming TLS.
2. **A backend-configuration charm**, providing the `cache-config` relation. Exactly one of:
   - [**Content Cache Backends Config**](https://charmhub.io/content-cache-backends-config) — a
     subordinate charm deployed onto the Content Cache unit. It provides a direct, minimal way
     to describe a set of backends (addresses, health check parameters, cache validity) with no
     routing or ingress features.
   - [**Ingress configurator**](https://charmhub.io/ingress-configurator) — a principal charm
     that translates its own configuration into the same `cache-config` relation data, but requires a
     `haproxy-route` relation before publishing a usable backend configuration. Paired with
     [**HAProxy**](https://charmhub.io/haproxy), it adds an ingress layer in front of Content Cache:
     hostname/path routing, TLS termination, DDoS protection, and health-check-based retries.

Everything else described below is optional and layers additional capability onto this
minimal pair.

## High-level deployment diagram

The diagram below shows Content Cache with every relation it supports. Solid arrows are the
required, functional relation (`cache-config`); dashed arrows are optional or conditional
integrations.

```{mermaid}
flowchart TB
    BackendConfig["Content Cache Backends Config<br/>or Ingress configurator"] -->|"cache-config<br/>(required)"| CC["Content Cache"]
    CC -->|"proxied requests"| Backend["Backend / origin"]
    CertProvider["Certificate provider<br/>(e.g. self-signed-certificates, lego)"] -.->|"certificates<br/>(optional: terminate TLS here)"| CC
    CertProvider -.->|"receive-ca-cert<br/>(only for private/untrusted HTTPS backend CA)"| CC
    COS["grafana-agent"] -.->|"cos-agent<br/>(optional: metrics & logs)"| CC
    CC <-.->|"content-cache-peers<br/>(automatic, multi-unit port sync)"| CCPeer["Content Cache<br/>(other units)"]
```

## Supported relations

| Relation endpoint | Interface | Direction | Required? | Purpose |
|---|---|---|---|---|
| `cache-config` | `content-cache-config` | provides | Yes | Backend addresses and per-backend cache/health-check settings. Without this relation the charm has nothing to cache. |
| `certificates` | `tls-certificates` | requires | Optional | Terminate TLS for incoming connections directly at Content Cache — standalone, or as a second TLS hop behind HAProxy (see {ref}`use cases <reference_deployment_architecture_use_cases>` below). |
| `receive-ca-cert` | `certificate_transfer` | requires | Conditionally | Trust a CA so nginx can verify backend certificates. Required only if any configured backend uses an `https://` URL; ignored entirely for HTTP-only backends. |
| `cos-agent` | `cos_agent` | provides | Optional | Ship metrics/logs to a Canonical Observability Stack (COS) via `grafana-agent` or an equivalent principal charm. |
| `content-cache-peers` | `content-cache-peers` | peers | Automatic | Coordinates per-relation port allocation across all units of the same Content Cache application. Not user-configured. |

(reference_deployment_architecture_use_cases)=

## How relations combine to support use cases

Each scenario below builds on the previous one by adding one more relation.

### Scenario 1: direct backend caching

```{mermaid}
flowchart LR
    CCBC["Content Cache Backends Config<br/>(subordinate)"] -->|"cache-config"| CC["Content Cache"]
    CC -->|"HTTP"| Backend["Backend / origin"]
```

The simplest supported deployment includes Content Cache Backends Config deployed as a subordinate
directly onto the Content Cache unit and describes one set of backends over plain HTTP. There
is no hostname/path-based routing and no TLS anywhere in the request path: each `cache-config`
relation is served on its own dedicated port (see {ref}`explanation_charm_design`), and callers
reach it directly at `http://<content-cache-unit-ip>:<port>`.

This pattern suits deployments with a small, fixed number of backend groups where clients (or
an existing load balancer) can address content-cache units and ports directly, and where
routing decisions do not need to change dynamically. Content Cache's own `certificates`
relation can also be used here, without HAProxy, if callers need to reach Content Cache over
HTTPS directly instead of plain HTTP — see {ref}`how_to_enable_https`.

### Scenario 2: add an ingress with TLS termination at the front and a second TLS hop to Content Cache

```{mermaid}
flowchart LR
    Client(["Client"]) -->|"🔒 HTTPS"| HAProxy["HAProxy"]
    HAProxy -->|"🔒 HTTPS"| CC["Content Cache"]
    CC -->|"HTTP"| Backend["Backend / origin"]
    IC["Ingress configurator"] -.->|"cache-config"| CC
    IC -.->|"haproxy-route"| HAProxy
    Lego["certificate provider<br/>charm"] -.->|"certificates"| HAProxy
    Lego -.->|"certificates"| CC
```

Content Cache Backends Config is replaced with Ingress configurator, which pairs with HAProxy
over `haproxy-route`. A certificate provider such as `lego` integrates with HAProxy's own
`certificates` relation, so the client speaks HTTPS to HAProxy. The certificate
provider charm also integrates directly with Content Cache's own `certificates` relation,
so Content Cache presents its own TLS certificate and listens with `ssl` on its allocated
port; HAProxy then forwards over this second, independent HTTPS hop instead of plain HTTP,
encrypting traffic for its entire path rather than only from the client to HAProxy. HAProxy
adds hostname/path-based routing, load balancing across Content Cache units, and DDoS
protection on top of what Scenario 1 provides. See {ref}`how_to_enable_https` and the
{ref}`tutorial <tutorial_advanced_ingress>` for a full walkthrough of this deployment.

### Scenario 3: add HTTPS to the backend

```{mermaid}
flowchart LR
    Client(["Client"]) -->|"🔒 HTTPS"| HAProxy["HAProxy"]
    HAProxy -->|"🔒 HTTPS"| CC["Content Cache"]
    CC -->|"🔒 HTTPS"| Backend["Backend / origin"]
    IC["Ingress configurator"] -.->|"cache-config<br/>(backend-protocol=https)"| CC
    IC -.->|"haproxy-route"| HAProxy
    Lego["certificate provider<br/>charm"] -.->|"certificates"| HAProxy
    Lego -.->|"certificates"| CC
    Lego -.->|"receive-ca-cert"| CC
```

Building on Scenario 2 (including its HAProxy-to-Content-Cache TLS hop), the backend is now
addressed as an `https://` URL. Content Cache must trust the backend's CA to verify its
certificate, so the certificate provider that issues the backend's certificate
also integrates over the `receive-ca-cert` relation directly with Content Cache. This is a
third, independent TLS relation: the certificates issued for HAProxy's client-facing
listener and for Content Cache's own listener do not need to share a CA with the one used to
protect the backend. For simplicity, the diagram reuses the same certificate provider charm for all three relations, but a
separate certificate provider instance for the backend's CA works the same way. Without
`receive-ca-cert`, Content Cache still proxies to the backend, but nginx cannot verify its
certificate against a trusted CA, so upstream TLS verification fails and requests to that
backend return an error. See {ref}`how_to_enable_https`.

### Observability

The `cos-agent` relation is additive to any of the scenarios above: integrating a
`grafana-agent` (or equivalent) principal charm collects nginx metrics and logs into COS
without changing how backends are configured. See {ref}`how_to_enable_cos`.

## What Content Cache does not do

To keep the intended deployment boundaries clear, Content Cache does not:

- Discover backends on its own — every backend must be described over `cache-config` by a
  related charm.
- Route by hostname or path — that requires Ingress configurator paired with HAProxy.
- Cache personalized or session-dependent content — see
  {ref}`explanation_charm_design` for the static-only caching assumption.
