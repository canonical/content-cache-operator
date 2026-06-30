---
myst:
  html_meta:
    "description lang=en": "Explanation of how the Content Cache charm caches static content, including cache miss and hit flow, expiry, eviction, and large-file considerations."
---

(explanation_caching_behavior)=

# Caching behavior

The charm uses nginx to cache static content from upstream backends. Understanding how nginx
fetches, stores, and expires cached responses helps operators predict behavior and plan
capacity — especially when caching large binary files such as Ubuntu ISO images.

## How caching works

### Cache miss: first request for a URL

When nginx receives a request for a URL that is not in the cache, it forwards the request to
an upstream backend. As the response arrives, nginx simultaneously:

- Streams the response body to the client.
- Writes the response body to disk at `/data/nginx/cache/<hostname>/`.

The charm sets
[`use_temp_path=off`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
on `proxy_cache_path`, so nginx writes directly to the final cache location during the
download. There is no intermediate temporary file.

### Cache hit: subsequent requests

Once a response is cached on disk, nginx serves it directly from disk without contacting the
upstream backend. The client receives the response faster, and the backend sees no load.

## Cache expiry and eviction

Two independent mechanisms remove cached responses.

**TTL expiry** — The `proxy-cache-valid` configuration on `content-cache-backends-config`
sets how long a cached response is considered fresh. For example, `200 1d` means a cached
200 response is valid for one day. After the TTL expires, the next request for that URL
triggers a fresh upstream fetch.

**Inactive eviction** — nginx also tracks when each cache entry was last accessed. If a
cached response is not requested within the
[`inactive`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
period, nginx evicts it from disk regardless of its TTL. The charm does not override this
parameter, so the nginx default of 10 minutes applies. A cached file that receives no
requests for 10 minutes is removed from disk — even if its TTL has not yet expired.

These two mechanisms are independent. The inactive timeout can evict a response before its
TTL expires, and a long TTL does not prevent eviction if the content is not accessed.

There is currently no charm configuration option to change the `inactive` timeout directly.

## Concurrent first-hit requests

The charm does not enable
[`proxy_cache_lock`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock).
When multiple clients simultaneously request the same uncached URL, nginx
starts a separate upstream fetch for each request rather than having the first fetch complete
while the rest wait.

For small files this behavior is usually acceptable — the window of concurrent cache misses is brief
and the bandwidth consumed is modest. For large files the impact is more significant (see
the next section).

## Large-file considerations

The behaviors above are amplified when caching large binary files such as Ubuntu ISO images.
Each file can be several gigabytes.

### Disk capacity

The charm does not set `max_size` or `min_free` on
[`proxy_cache_path`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path).
nginx's cache manager only performs LRU eviction when one of those parameters is configured —
without them, it has no threshold to act on. nginx will therefore cache files until the
filesystem is full, with no automatic cleanup.

Operators should:

- Provision a dedicated large volume mounted at `/data/nginx/cache/` before deploying for
  large-file caching.
- Monitor disk usage and set up alerts before the filesystem fills up.

When the disk fills up, nginx fails to write new cache entries. Existing cached files remain
accessible, but requests for uncached files will fail if nginx cannot write the response to
disk during the upstream fetch.

### Inactive eviction impact

For files accessed periodically — for example, ISO images downloaded during machine
provisioning runs — the 10-minute inactive timeout may cause repeated upstream re-fetches.
Each re-fetch transfers the full file again from the upstream backend.

### Concurrent first-hit bandwidth

Without `proxy_cache_lock`, multiple concurrent first-hit requests for the same uncached
large file each trigger a separate upstream fetch. For a multi-gigabyte file, this multiplies
upstream bandwidth consumption during the caching window. Once the file is fully cached, all
subsequent requests are served from disk. The concurrent-fetch problem only affects the window
before the file is fully stored.

