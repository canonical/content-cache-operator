---
myst:
  html_meta:
    "description lang=en": "Explanation of how the Content Cache charm handles large binary files such as Ubuntu ISO images, including disk, RAM, and eviction behavior."
---

(explanation_large_file_caching)=

# Large-file caching

The charm supports caching large binary files such as Ubuntu ISO images. Because each ISO
can be several gigabytes, the behaviors that matter most differ from caching small web assets:
disk capacity becomes the dominant resource concern, not RAM.

## How large-file caching works

When a client requests a file that is not yet cached, nginx fetches the full response from
the upstream backend and simultaneously streams it to the client and to the cache directory
at `/data/nginx/cache/<hostname>/`. The charm sets
[`use_temp_path=off`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
on `proxy_cache_path`, so the file is written directly to its final cache location during the
download. There is no double write to a temporary location first.

Once the file is fully received and written, subsequent requests are served directly from disk
without contacting the upstream. There is no per-entry file size limit other than available
disk space.

RAM is not a concern for large files. The
[`keys_zone`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
(10 MB per hostname) stores only cache metadata — keys and timestamps — not file bodies.
A 10 MB zone holds approximately 80,000 entries. Even with thousands of cached files, this
zone will not fill up.

## Disk capacity

The charm does not set a `max_size` limit on
[`proxy_cache_path`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path).
nginx will cache files until the filesystem is full. A single Ubuntu ISO is typically 1–4 GB.
With no cap, caching even a modest number of ISO releases can exhaust the disk of the host
machine.

Operators should:

- Provision a dedicated large volume mounted at `/data/nginx/cache/` before deploying for
  large-file caching.
- Monitor disk usage and set up alerts before the filesystem fills up.

When the disk fills up, nginx will fail to write new cache entries. Existing cached files
remain accessible, but requests for uncached files will fail if nginx cannot write the
response to disk during the upstream fetch.

## Cache eviction and the inactive timeout

nginx evicts a cached file if it is not accessed within the `inactive` period. The charm does
not override this parameter, so the
[nginx default of 10 minutes](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
applies. A cached ISO that receives no requests for 10 minutes is removed from disk,
regardless of any TTL set in `proxy-cache-valid`.

For ISOs accessed periodically rather than continuously — for example, downloaded during
machine provisioning runs — this default may cause repeated upstream re-fetches. Operators can
set a long `proxy-cache-valid` TTL (for example, `200 7d`) via the
`content-cache-backends-config` charm. This does not change the `inactive` timeout, but it
ensures that files accessed regularly do not expire prematurely between hits.

There is currently no charm configuration option to change the `inactive` timeout directly.

## Concurrent first-hit requests

The charm does not enable
[`proxy_cache_lock`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock).
When multiple clients simultaneously request the same file that is not yet cached, nginx
starts a separate upstream fetch for each client rather than having the first fetch complete
while the rest wait. For large files, this multiplies upstream bandwidth consumption during
the caching window — for example, ten concurrent first-hit requests for a 2 GB ISO consume
20 GB of upstream bandwidth in parallel.

Once the first fetch completes and the file is stored in cache, all subsequent requests are
served from disk. The concurrent-fetch problem only affects the window before the file is
fully cached.

## Quick reference

| Behavior | Detail |
|---|---|
| File size limit per cache entry | None — disk space is the only limit |
| Disk cap across all cached files | None — `max_size` is not set |
| RAM used for file bodies | None — file bodies live on disk only |
| RAM used for cache metadata | `keys_zone=<hostname>:10m` (~80,000 entries per hostname) |
| Write path on first fetch | Direct to final cache location (`use_temp_path=off`) |
| Cache eviction (inactive timeout) | nginx default: 10 minutes of no access |
| Cache TTL per status code | Configurable via `proxy-cache-valid` on `content-cache-backends-config` |
| Concurrent first-hit requests | Each triggers a separate upstream fetch (`proxy_cache_lock` not set) |
| Disk full behavior | New cache writes fail; existing cached files remain accessible |
