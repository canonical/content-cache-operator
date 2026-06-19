# Design: Large-file caching (Ubuntu ISO images) explanation page

**Date:** 2026-06-19
**Branch:** docs/image-cache-isd-5928
**Ticket:** ISD-5928

## Goal

Add a new Explanation page to `docs/explanation/` documenting how the content-cache charm
handles large binary files such as Ubuntu ISO images. The page answers:

- How does large-file (image) caching work?
- Is RAM a concern for large files?
- What happens when disk is full?
- How does cache eviction affect infrequently-accessed files?
- What happens when multiple clients concurrently request the same uncached large file?

## Audience

Operators who run the charm in production.

## Page type

Diátaxis: Explanation — narrative sections explaining design and behavior, ending with a
structured quick-reference table.

## File location

`docs/explanation/large-file-caching.md`

Also update `docs/explanation/index.md` toctree.

## Sections

### 1. Introduction
Establish that the charm supports large binary files (e.g., Ubuntu ISOs). Disk is the
dominant resource concern, not RAM.

### 2. How large-file caching works
- nginx fetches the full file from upstream on cache miss, streams to client and disk simultaneously
- `use_temp_path=off` → single write directly to final cache location
- No file-size limit per entry (only disk space limits)
- RAM keys_zone stores metadata only (~80,000 entries per 10 MB zone); not a concern

### 3. Disk capacity
- No `max_size` set on `proxy_cache_path` → nginx fills disk
- Ubuntu ISOs: 1–4 GB each
- Operators must provision a large volume at `/data/nginx/cache/`
- When disk is full: new cache writes fail; existing cached files remain accessible

### 4. Cache eviction and the inactive timeout
- nginx default `inactive` = 10 minutes (not overridden by charm)
- A cached ISO not accessed within 10 minutes is evicted from disk
- Operators can set a long `proxy-cache-valid` TTL on `content-cache-backends-config`
  to avoid premature expiry when files are regularly accessed
- No charm config option to change `inactive` timeout directly

### 5. Concurrent first-hit requests
- `proxy_cache_lock` not set → each concurrent request for an uncached file triggers
  a separate upstream fetch
- For large files: multiplied upstream bandwidth during the caching window

### 6. Quick-reference table
Summary of all behaviors and limits:
| Behavior | Detail |
|---|---|
| File size limit per entry | None (disk space only) |
| Disk cap | None — `max_size` not set |
| RAM for file bodies | None — bodies on disk |
| RAM for cache metadata | `keys_zone=<hostname>:10m` (~80,000 entries) |
| Write path on first fetch | Direct to cache location (`use_temp_path=off`) |
| Inactive eviction timeout | nginx default: 10 minutes |
| Cache TTL | Configurable via `proxy-cache-valid` |
| Concurrent first-hit requests | Each triggers separate upstream fetch |
| Disk full behavior | New writes fail; existing entries stay |

## Source verification requirements

Every claim must be verified against:
- `content-cache/src/nginx_manager.py` (charm code)
- nginx official documentation (https://nginx.org/en/docs/) for nginx defaults
