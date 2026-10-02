---
myst:
  html_meta:
    "description lang=en": "Explanation of how the Content Cache charm caches static content, including cache miss and hit flow, expiry, eviction, and large-file considerations."
---

(explanation_caching_behavior)=

# Caching behavior

The charm uses nginx to cache static content from upstream backends. Understanding how nginx
fetches, stores, and expires cached responses helps operators predict behavior and plan
capacity, especially when caching large binary files such as Ubuntu ISO images.

## How caching works

### Cache miss: first request for a URL

When nginx receives a request for a URL that is not in the cache, it forwards the request to
an upstream backend. As the response arrives, nginx simultaneously:

- Streams the response body to the client.
- Writes the response body to disk at `/data/nginx/cache/<port>/`.

The charm sets
[`use_temp_path=off`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
on `proxy_cache_path`, so nginx writes directly to the final cache location during the
download. There is no intermediate temporary file.

### Cache hit: subsequent requests

Once a response is cached on disk, nginx serves it directly from disk without contacting the
upstream backend. The client receives the response faster, and the backend sees no load.

## Cache expiry and eviction

Two independent mechanisms remove cached responses.

**TTL expiry:** The `proxy_cache_valid` field of the `cache-config` relation data (for example,
`proxy-cache-valid` on `content-cache-backends-config`, or
`cache-proxy-cache-valid` on `ingress-configurator`)
sets how long a cached response is considered fresh. For example, `200 1d` means a cached
200 response is valid for one day. After the TTL expires, the next request for that URL
triggers a fresh upstream fetch.

**Inactive eviction:** nginx also tracks when each cache entry was last accessed. If a
cached response is not requested within the
[`inactive`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
period, nginx evicts it from disk regardless of its TTL. This period is controlled by the
`cache-inactive` configuration on `content-cache-backends-config`, which defaults to `10m`.
A cached file that receives no requests within that window is removed from disk, even if
its TTL has not yet expired. Increase `cache-inactive` for files that are accessed on long
periodic cycles.

These two mechanisms are independent. The inactive timeout can evict a response before its
TTL expires, and a long TTL does not prevent eviction if the content is not accessed.

### Upstream cache headers

nginx evaluates upstream response headers before applying `proxy_cache_valid`. As documented
in [`proxy_cache_valid`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_valid),
response headers take higher priority:

- `X-Accel-Expires`: sets the cache TTL in seconds; overrides `proxy_cache_valid`.
- `Cache-Control` or `Expires`: used to determine TTL when `X-Accel-Expires` is absent.
- `Set-Cookie`: if present, the response is **not cached**, regardless of `proxy_cache_valid`.
- `Vary: *`: if present, the response is **not cached**.

The charm does not set
[`proxy_ignore_headers`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ignore_headers),
so these defaults apply. Backends that send `Cache-Control: no-store` or `Set-Cookie` on
responses intended to be cached will silently bypass the cache.

The [`inactive`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
timeout applies to all cached entries regardless of their upstream cache headers. A response
cached with `Cache-Control: max-age=86400` is still evicted if it receives no requests within
the inactive window.

## Concurrent first-hit requests

The charm enables
[`proxy_cache_lock`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock)
on all cache locations. When multiple clients simultaneously request the same uncached URL,
only the first request triggers an upstream fetch. The remaining requests wait for the
first fetch to populate the cache and are then served from disk, instead of each triggering
a separate upstream fetch.

nginx defaults `proxy_cache_lock_age` and `proxy_cache_lock_timeout` to five seconds each; once
either bound elapses, a waiting request is allowed to send its own request upstream rather than
keep waiting. The point of enabling the lock in this charm is to avoid duplicate fetches
of large files that can take much longer than five seconds to download; therefore, the charm
sets both directives to 300 seconds so waiting requests give the first fetch a realistic
chance to finish. Downloads that exceed 300 seconds can still result in more than one
upstream fetch for the same URL.

Setting both directives to 300 seconds reduces redundant load on the backend during
concurrent cache misses, which matters most for large files where a stampede of simultaneous
fetches would otherwise consume significant bandwidth (see the next section).

## Large-file considerations

The behaviors above are amplified when caching large binary files such as Ubuntu ISO images.
Each file can be several gigabytes.

### Disk capacity

The charm does not set `min_free` on
[`proxy_cache_path`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path).
The `cache-max-size` configuration on `content-cache-backends-config` maps to `max_size` on
`proxy_cache_path` and defaults to an empty string (no limit). When `cache-max-size` is left
unset, there is no size-based threshold for nginx's cache manager to evict against, so disk
usage is bounded only by the `inactive` eviction described above. Leaving `cache-max-size`
unset is not the same as no automatic cleanup: files that are accessed regularly are never
considered inactive, so they are never evicted by that mechanism either, and can still fill
the filesystem if there is no size limit configured. Setting `cache-max-size` (for example
`2g`) lets nginx evict least-recently-used entries once the limit is reached, regardless of
how recently they were accessed.

Operators should:

- Set `cache-max-size` to a sensible limit, or provision a dedicated large volume mounted at
  `/data/nginx/cache/` before deploying for large-file caching if the size is left unbounded.
- Monitor disk usage and set up alerts before the filesystem fills up.

When the disk fills up, nginx fails to write new cache entries. Existing cached files remain
accessible, but requests for uncached files will fail if nginx cannot write the response to
disk during the upstream fetch.

### Inactive eviction impact

For files accessed periodically (for example, ISO images downloaded during machine
provisioning runs), the 10-minute inactive timeout may cause repeated upstream re-fetches.
Each re-fetch transfers the full file again from the upstream backend.

### Concurrent first-hit bandwidth

Without `proxy_cache_lock`, multiple concurrent first-hit requests for the same uncached
large file each trigger a separate upstream fetch. For a multi-gigabyte file, this multiplies
upstream bandwidth consumption during the caching window. Once the file is fully cached, all
subsequent requests are served from disk. The concurrent-fetch problem only affects the window
before the file is fully stored.

