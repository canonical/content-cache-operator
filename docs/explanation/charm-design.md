---
myst:
  html_meta:
    "description lang=en": "Explanation of the Content Cache charm's design decisions and how they affect caching behavior, memory usage, failover, and TLS."
---

(explanation_charm_design)=

# Charm design and how it works under the hood

The Content Cache charm makes deliberate, opinionated design decisions to optimize for
simplicity and static content caching. Understanding those decisions and how they affect
behavior in real deployments can help you predict outcomes and avoid unexpected issues.

## Static-only caching assumption

The charm is built exclusively for caching static, non-personalized content such as image
assets, CSS files, and HTML pages. This content should look the same regardless of who requests it.

nginx identifies a cacheable response by its cache key. The charm does not set a
[`proxy_cache_key`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_key)
directive, so nginx uses its default: `$scheme$proxy_host$request_uri`.

`$request_uri` includes the path and any query string. For example,
`GET /page?lang=en` and `GET /page?lang=fr` produce different cache keys and are stored
as separate cache entries, and therefore query-parameter-based variation works correctly.
The key does not consider request headers such as `Cookie`, `Authorization`, or
`X-User-ID`.

This means that two requests with the same URL but different session cookies will share a
single cache entry. The first response is cached and served to every subsequent requester of
that URL, regardless of their session or identity. For personalized or session-dependent
content, this behavior produces incorrect results.

The charm is therefore not suitable for:

- Pages that vary by logged-in user (e.g. dashboards, account pages)
- API responses that differ based on cookies or auth tokens (same URL, different users)
- Any content where the correct response depends on the identity of the user making the request

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

The [`proxy_cache`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache)
directive (set at the server block level) ties this location to its hostname's
dedicated cache zone.

## Cache storage

nginx uses a two-tier storage model for caching: disk and RAM.

Disk stores the actual cached response bodies. Each hostname gets its own directory:

```
/data/nginx/cache/<hostname>/
```

RAM stores the cache metadata (keys, expiry information, and file paths). The charm
allocates a fixed 10 MB keys zone per hostname via the
[`proxy_cache_path`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
directive:

```nginx
proxy_cache_path /data/nginx/cache/example.com
    use_temp_path=off
    levels=1:2
    keys_zone=example.com:10m;
```

The 10 MB limit is fixed in the charm and cannot be changed via configuration. For most static
content deployments this is sufficient: per the nginx docs,
10 MB supports approximately 80,000 cached entries.

### What happens when the keys zone fills up

When the keys zone is full, nginx applies
[LRU (Least Recently Used) eviction](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path):
the metadata entry for the least recently accessed cache item is removed from the shared memory zone.

### Disk expiry and cache lifetime

Disk entries expire according to
[`proxy_cache_valid`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_valid),
which maps HTTP response codes to TTLs. For example:

```
proxy-cache-valid: '["200 302 1h", "404 1m"]'
```

This directive caches 200 and 302 responses for one hour, and 404 responses for one minute. Responses
not matched by any rule are not cached.

### Multi-host isolation

Each hostname configured via a `content-cache-backends-config` relation gets:

- Its own cache directory (`/data/nginx/cache/<hostname>/`)
- Its own RAM keys zone (`keys_zone=<hostname>:10m`)
- Its own upstream block and log files

There is no cross-hostname competition for RAM. Each hostname has its own `keys_zone`
allocation, so one hostname's cache metadata cannot evict another's. Disk capacity, however,
is shared across all hostnames on the same filesystem. Adding or removing a
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
| `healthcheck-ssl-verify` | Verify SSL cert on HTTPS checks (set to `false` to skip verification) | `true` |

The checker uses fall/rise thresholds to avoid flapping:

- A backend is marked down after 3 consecutive failures (`fall=3`)
- A backend is marked up again after 2 consecutive successes (`rise=2`)

The generated Lua block for a single backend looks like (using non-default values for
`healthcheck-path` and `protocol` as an example):

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

[`fail-timeout`](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#server) is a
separate nginx concept from the Lua health checker. When nginx tries to
proxy a request to a backend and that individual request fails, the backend is skipped for the
`fail-timeout` duration (default `30s`) before being retried. This operates at the request
level, not the background health check level.

### All backends unavailable

If all backends for a hostname are simultaneously marked down (either by the health checker or
by `fail-timeout`), nginx returns 502 Bad Gateway to the client. Cached content for the
affected paths may still be served if the entries are still valid according to `proxy-cache-valid`.
nginx does not serve stale content beyond its TTL by default.

## TLS termination

TLS is terminated by the nginx instance managed by this charm. Backends are always addressed
directly by IP address over the protocol specified by the `protocol` configuration option
(`http` or `https`).

TLS certificates are obtained via the Juju `certificates` relation
(using the `tls-certificates` interface). When a `content-cache-backends-config` relation
provides a hostname, the charm requests a certificate for that hostname.

### Behavior when certificates are not yet available

If the `certificates` relation exists but the certificate for a hostname has not yet been
issued, the charm enters `Maintenance` status and does not reload nginx with the updated
configuration until all required certificates are available. It will not fall back to serving
the hostname over plain HTTP.

This is an intentional security decision, as a charm that has been told to expect TLS should not
silently serve unencrypted traffic because a certificate is delayed.

If no `certificates` relation is present, the charm does not add a `listen 443 ssl` directive
to the nginx server block. nginx then falls back to its default behavior of listening on port 80,
serving all traffic over plain HTTP with no TLS.
