---
myst:
  html_meta:
    "description lang=en": "Explanation of the Content Cache charm's design decisions and how they affect caching behaviour, memory usage, failover, and TLS."
---

(explanation_charm_design)=

# Charm design and how it works under the hood

The Content Cache charm makes deliberate, opinionated design decisions to optimise for
simplicity and static content caching. This page explains those decisions and how they affect
behaviour in real deployments, so that you can predict outcomes and avoid unexpected issues.

## Static-only caching assumption

The most important design decision is that the charm is built exclusively for caching static,
non-personalised content. Think of it as a lightweight CDN in front of your backends: image
assets, CSS files, HTML pages that look the same regardless of who requests them.

nginx identifies a cacheable response by its cache key. The charm configures nginx with
the default cache key:

```
$scheme$proxy_host$request_uri
```

`$request_uri` includes the path and any query string. This means:

- `GET /page?lang=en` and `GET /page?lang=fr` produce different cache keys and are stored
  as separate cache entries — query-parameter-based variation works correctly.
- However, the key does not consider request headers such as `Cookie`, `Authorization`, or
  `X-User-ID`.

This means that two requests with the same URL but different session cookies will share a
single cache entry. The first response is cached and served to every subsequent requester of
that URL, regardless of their session or identity. For personalised or session-dependent
content, this produces incorrect results.

The charm is therefore not suitable for:

- Pages that vary by logged-in user (e.g. dashboards, account pages)
- API responses that differ based on cookies or auth tokens (same URL, different users)
- Any content where the correct response depends on the requester's identity

It is well-suited for:

- Public marketing pages and blog posts
- Static asset files (JS, CSS, fonts, images)
- Documentation sites
- Content that is identical for every visitor, or that varies only by URL/query parameters

The generated nginx location block looks like:

```nginx
location / {
    proxy_pass http://<upstream-uuid>/;
    proxy_set_header Host "example.com";
    proxy_cache_valid 200 302 1h;
    proxy_cache_valid 404 1m;
}
```

The `proxy_cache` directive (set at the server block level) ties this location to its hostname's
dedicated cache zone.

## Cache storage: disk and RAM

nginx uses a two-tier storage model for caching:

Disk stores the actual cached response bodies. Each hostname gets its own directory:

```
/data/nginx/cache/<hostname>/
```

RAM stores the cache metadata (keys, expiry information, and file paths). The charm
allocates a fixed 10 MB keys zone per hostname:

```nginx
proxy_cache_path /data/nginx/cache/example.com
    use_temp_path=off
    levels=1:2
    keys_zone=example.com:10m;
```

The 10 MB limit is fixed in the charm and cannot be changed via configuration. For most static
content deployments this is sufficient: nginx can hold roughly 80,000 cache keys per megabyte,
meaning 10 MB supports approximately 800,000 cached entries.

### What happens when the keys zone fills up

When the keys zone is full, nginx applies LRU (Least Recently Used) eviction: the metadata
entry for the least recently accessed cache item is removed from RAM first. This does not
immediately delete the cached response from disk. It means that the next request for that URL
will be treated as a cache miss, and nginx will re-fetch the response from a backend to
repopulate both the disk entry and the RAM key.

In practice, a full keys zone under sustained traffic causes an increase in backend requests
as evicted keys are re-fetched, but does not cause data loss or service interruption.

### Disk expiry and cache lifetime

Disk entries are expired according to `proxy-cache-valid`, which maps HTTP response codes to
TTLs. For example:

```
proxy-cache-valid: '["200 302 1h", "404 1m"]'
```

This caches 200 and 302 responses for one hour, and 404 responses for one minute. Responses
not matched by any rule are not cached.

### Multi-host isolation

Each hostname configured via a `content-cache-backends-config` relation gets:

- Its own cache directory (`/data/nginx/cache/<hostname>/`)
- Its own RAM keys zone (`keys_zone=<hostname>:10m`)
- Its own upstream block and log files

There is no cross-hostname competition for RAM or disk. Adding or removing a
`content-cache-backends-config` relation only affects that hostname's configuration; other
hostnames continue serving from their own caches uninterrupted.

## Backend health checks and failover

The charm uses the [lua-resty-upstream-healthcheck](https://github.com/openresty/lua-resty-upstream-healthcheck)
module to actively monitor backend health. A Lua worker runs inside each nginx worker process
and periodically probes each backend in the background.

The health check parameters are configured per relation:

| Parameter | Description | Default |
|---|---|---|
| `healthcheck-interval` | Time between checks (ms) | 10000 |
| `healthcheck-path` | URL path to probe | `/` |
| `healthcheck-valid-status` | HTTP codes considered healthy | `200` |
| `healthcheck-ssl-verify` | Verify SSL cert on HTTPS checks | `true` |

The checker uses fall/rise thresholds to avoid flapping:

- A backend is marked down after 3 consecutive failures (`fall=3`)
- A backend is marked up again after 2 consecutive successes (`rise=2`)

The generated Lua block for a single backend looks like:

```lua
ok, err = hc.spawn_checker{
    shm = "healthcheck",
    upstream = "<upstream-uuid>",
    type = "https",
    http_req = "GET /health HTTP/1.0\r\nHost: example.com\r\n\r\n",
    port = 443,
    interval = 10000,
    timeout = 1000,
    fall = 3,
    rise = 2,
    valid_statuses = {200},
    concurrency = 10,
    host = "example.com",
    ssl_verify = true
}
```

### The `fail-timeout` parameter

`fail-timeout` is a separate nginx concept from the Lua health checker. When nginx tries to
proxy a request to a backend and that individual request fails, the backend is skipped for the
`fail-timeout` duration (default `30s`) before being retried. This operates at the request
level, not the background health check level.

### All backends unavailable

If all backends for a hostname are simultaneously marked down (either by the health checker or
by `fail-timeout`), nginx returns 502 Bad Gateway to the client. Cached content for the
affected paths may still be served if the entries are still valid according to `proxy-cache-valid`.
nginx does not serve stale content beyond its TTL by default.

## TLS termination

TLS is terminated at the nginx instance managed by this charm. Backends are always addressed
directly by IP address over the protocol specified by the `protocol` configuration option
(`http` or `https`).

TLS certificates are obtained via the Juju `certificates` integration
(using the `tls-certificates` interface). When a `content-cache-backends-config` relation
provides a hostname, the charm requests a certificate for that hostname.

### Behaviour when certificates are not yet available

If the `certificates` integration exists but the certificate for a hostname has not yet been
issued, the charm enters Maintenance status and does not load any nginx configuration
until all required certificates are available. It will not fall back to serving the hostname
over plain HTTP.

This is an intentional security decision: a charm that has been told to expect TLS should not
silently serve unencrypted traffic because a certificate is delayed.

If no `certificates` integration is present, the charm serves all traffic over HTTP on port 80
with no TLS.

## Summary of design opinions

| Decision | Consequence |
|---|---|
| Cache key does not include auth/session headers | Dynamic, personalised content is served incorrectly |
| Keys zone fixed at 10 MB per hostname | High-traffic deployments with many unique URLs may see increased backend requests due to LRU eviction |
| Each hostname is fully isolated | No cross-hostname cache pollution; no shared RAM competition |
| TLS required if certificates integration is present | No silent HTTP fallback when certs are expected but not yet available |
| All-backends-down → 502 | No stale-cache fallback beyond TTL |
