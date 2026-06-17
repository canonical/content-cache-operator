# Design Doc: Explanation Page — Charm Design and How It Works Under the Hood

**Date:** 2026-06-17  
**Ticket:** ISD-5927  
**Branch:** docs/explanation-isd-5927  
**Status:** Approved

---

## Purpose

Create a single Explanation page (Diátaxis) for operators and DevOps using the content-cache charm in production. The page explains the opinionated design choices made by the charm and how those choices affect behaviour in real deployments.

## Audience

Operators / DevOps running the charm in production. Not developer contributors.

## Structure

Single page at `docs/explanation/charm-design.md`, added to the docs toctree under a new `explanation/` section.

### Section 1 — Introduction
Brief framing: the charm makes deliberate, opinionated design decisions optimised for simplicity and static content caching. Understanding these decisions helps operators predict behaviour and avoid unexpected issues.

### Section 2 — Static-Only Caching Assumption (key design opinion)
- The charm is designed exclusively for static, non-personalised content (CDN-like use case)
- nginx cache key: `$scheme$proxy_host$request_uri` — includes query parameters but NOT session headers
- Two requests with different query strings (`?lang=en`, `?lang=fr`) produce different cache keys and are cached separately — query-parameter variation works correctly
- Two requests with the same URL but different cookies/auth headers share the same cache entry — session/identity-based variation is NOT handled correctly
- Includes a generated nginx location block snippet showing `proxy_pass` and `proxy_cache`

### Section 3 — Cache Storage: Disk and RAM
- Disk: `/data/nginx/cache/<hostname>/` — actual response bodies
- RAM (`keys_zone`): 10 MB per hostname (hardcoded), stores cache metadata keys
- RAM overload behaviour: LRU eviction of metadata keys; disk data not deleted, but evicted keys cause cache misses → re-fetch from backend
- Each hostname has its own independent `keys_zone` and cache directory — no cross-hostname RAM competition
- `proxy_cache_valid` controls TTL-based disk expiry
- Includes generated `proxy_cache_path` nginx config snippet

### Section 4 — Backend Health Checks and Failover
- Lua-based health checker (`lua-resty-upstream-healthcheck`) runs in nginx worker background
- `fall=3` (3 consecutive failures → backend marked down), `rise=2` (2 successes → back up)
- `healthcheck-interval`: time between checks in ms
- `fail-timeout`: after a proxying failure, backend is skipped for this duration
- All backends down → nginx returns 502 Bad Gateway
- Includes generated Lua healthcheck block snippet

### Section 5 — TLS Termination
- TLS is terminated at nginx; backends are addressed by IP
- Certificates obtained via Juju `tls-certificates` integration
- If TLS integration exists but certs not yet available: charm waits in Maintenance (does NOT fall back to plain HTTP)
- If no TLS integration: HTTP only (port 80)
- Design opinion: security over availability when certs are expected but not yet provisioned

### Section 6 — Multi-Host Isolation
- Each `content-cache-backends-config` relation = independent nginx virtual host
- Own cache directory, keys_zone, upstream block, log files
- No shared cache state between hostnames
- Adding/removing a config charm relation only affects that host

## File Locations

- Spec: `docs/superpowers/specs/2026-06-17-explanation-charm-design-design.md`
- Page: `docs/explanation/charm-design.md`
- Index: `docs/explanation/index.md`
- Toctree entry in: `docs/index.md`

## Out of Scope

- Contributing / developer documentation
- How-to procedures (those belong in how-to/)
- Reference config parameters (those belong in reference/)
