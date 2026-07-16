---
myst:
  html_meta:
    "description lang=en": "Explanation of the Content Cache charm's design decisions and how they affect caching behavior, memory usage, failover, and backend protocols."
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
directive, so nginx uses the default `$scheme$proxy_host$request_uri`.

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

It is well-suited for static asset files (JS, CSS, fonts, images, binary packages, and
archives), including use cases such as:

- Public marketing pages and blog posts
- Documentation sites
- Software distribution mirrors (package repositories, release archives)
- Any content that is identical for every visitor, or varies only by URL or query parameters

For each `cache-config` relation, the charm generates a single nginx server block with one
`location /` block that proxies all traffic to the configured backends. The following
example shows the directives relevant to caching:

```nginx
server {
    listen 8080;
    proxy_cache 8080;

    location / {
        proxy_pass https://<upstream-uuid>/;
        proxy_cache_valid 200 302 1h;
        proxy_cache_valid 404 1m;
    }
}
```

The [`proxy_cache`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache)
directive (set at the server block level) ties this location to its dedicated cache zone.

## Port allocation

The charm allocates a unique TCP port to each `cache-config` relation. Ports are assigned
from a fixed range starting at `8080` and are stable across charm restarts. The same
relation always receives the same port for the lifetime of that relation, stored via Juju's
`StoredState`.

This means each configured backend is reachable at a distinct port on the content-cache
unit's IP address:

```
http://<unit-ip>:8080   →  backends from relation 1
http://<unit-ip>:8081   →  backends from relation 2
```

An ingress component (such as haproxy with the `ingress-configurator` charm) is expected
to sit in front of the content-cache unit and route incoming requests to the appropriate
port based on hostname or path rules.

## Cache storage

nginx uses a two-tier storage model for caching: disk and RAM.

Disk stores the actual cached response bodies. Each `cache-config` relation gets its own
directory, named after its allocated port:

```
/data/nginx/cache/<port>/
```

RAM stores the cache metadata (keys, expiry information, and file paths). The charm
allocates a fixed 10 MB keys zone per relation via the
[`proxy_cache_path`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
directive:

```nginx
proxy_cache_path /data/nginx/cache/8080
    use_temp_path=off
    levels=1:2
    keys_zone=8080:10m;
```

The 10 MB limit is fixed in the charm and cannot be changed via configuration. For most static
content deployments this is sufficient: per the nginx docs,
10 MB supports approximately 80,000 cached entries.

### When the keys zone fills up

When the keys zone is full, nginx applies
[LRU (Least Recently Used) eviction](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path):
the metadata entry for the least recently accessed cache item is removed from the shared memory zone.

### Disk expiry and cache lifetime

Disk entries expire according to
[`proxy_cache_valid`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_valid),
which maps HTTP response codes to TTLs. This value is set via the `proxy-cache-valid` option
on `content-cache-backends-config` and applies per relation. For example:

```
proxy-cache-valid: '["200 302 1h", "404 1m"]'
```

This directive caches 200 and 302 responses for one hour, and 404 responses for one minute. Responses
not matched by any rule are not cached.

### Per-backend isolation

Each `content-cache-backends-config` relation configured via `cache-config` gets:

- Its own cache directory (`/data/nginx/cache/<port>/`)
- Its own RAM keys zone (`keys_zone=<port>:10m`)
- Its own upstream block and log files

There is no cross-relation competition for RAM. Each relation has its own `keys_zone`
allocation, so cache metadata for one backend cannot evict the cache for another. Disk capacity, however,
is shared across all relations on the same filesystem. Adding or removing a
`content-cache-backends-config` relation only affects that relation's configuration; other
backends continue serving from their own caches uninterrupted.

## Backend health checks and failover

The charm uses the [lua-resty-upstream-healthcheck](https://github.com/openresty/lua-resty-upstream-healthcheck)
module to actively monitor backend health. A Lua worker runs inside each nginx worker process
and periodically probes each backend in the background.

The health check parameters are configured per relation:

| Parameter | Description | Default |
|---|---|---|
| `healthcheck-interval` | Time between checks (ms) | `10000` |
| `healthcheck-path` | URL path to probe | `/` |
| `healthcheck-valid-status` | HTTP codes considered healthy | `200` |
| `healthcheck-ssl-verify` | Verify SSL cert on HTTPS checks (set to `false` to skip verification) | `true` |

The checker uses fall/rise thresholds to avoid flapping:

- A backend is marked down after 3 consecutive failures (`fall=3`)
- A backend is marked up again after 2 consecutive successes (`rise=2`)

The following example shows the generated Lua block for a single backend
using non-default values for `healthcheck-path` and `protocol`:

```lua
ok, err = hc.spawn_checker{
    shm = "healthcheck",
    upstream = "<upstream-uuid>",
    type = "https",
    http_req = "GET /health HTTP/1.0\r\n\r\n",
    port = 443,
    interval = 10000,
    timeout = 1000,
    fall = 3,
    rise = 2,
    valid_statuses = {200},
    concurrency = 10,
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

If all backends for a relation are simultaneously marked down (either by the health checker or
by `fail-timeout`), nginx returns 502 Bad Gateway to the client. Cached content for the
affected paths may still be served if the entries are still valid according to `proxy-cache-valid`.
nginx does not serve stale content beyond its TTL by default.

## Backend protocol (HTTP vs HTTPS)

Backends are always addressed directly by IP address over the protocol specified by the
`protocol` configuration option (`http` or `https`).

When `protocol` is set to `https`, nginx connects to the backend over TLS. The charm does
not manage TLS certificates for the incoming (listening) side. TLS termination for
incoming client traffic is expected to be handled by an upstream ingress (such as haproxy with
the `ingress-configurator` charm).
