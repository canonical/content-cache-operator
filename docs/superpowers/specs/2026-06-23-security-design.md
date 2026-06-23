# Design: Security explanation page

**Date:** 2026-06-23
**Branch:** docs/security-isd-5931
**Ticket:** ISD-5931

## Goal

Add a new Explanation page to `docs/explanation/` covering the security design decisions of
the content-cache charm. The page addresses three questions from the ticket:

1. Is native auth planned, or must users add another component?
2. What parameters/configurations exist to secure cached information?
3. How does the charm protect the cache, and what additional integrations can help?

## Audience

Juju operators deploying the charm in production.

## Tone

Honest and balanced — equal weight to what the charm does and does not protect.

## Page type

Diátaxis: Explanation — narrative sections organized by security boundary, ending with a
best-practices summary table.

## File location

`docs/explanation/security.md`

Also update `docs/explanation/index.md` toctree.

## Structure (boundary-based)

### 1. Introduction
Three security boundaries: client → charm, charm → backend, internal nginx process.

### 2. Client → charm boundary
- TLS: via `tls-certificates` integration; without it, HTTP only
- Client auth: none — intentional design for public static content; operators must add
  a reverse proxy/WAF in front if access control is needed
- Rate limiting: not configured; operators must add at upstream component

### 3. Charm → backend boundary
- `protocol` config defaults to `https`
- `healthcheck-ssl-verify` defaults to `true`; affects healthchecks only, NOT proxy_pass

### 4. Internal boundary
- nginx runs as `www-data` (low-privilege)
- PEM files at `/etc/nginx/certificates/<hostname>.pem`, owned by `www-data`, chmod `0o644`
  (private key readable by local users — restrict machine access)
- Status pages restricted to `127.0.0.1` only
- `shell=False` on all subprocess calls

### 5. Cached data risks
- Cache key excludes Cookie/Authorization headers — personalized content must not be routed
  through the charm
- No built-in cache purge — must wait for TTL/inactive expiry or implement at nginx level

### 6. Best-practices summary table

| Practice | Recommendation |
|---|---|
| Enable TLS | Integrate with a `tls-certificates` provider charm |
| Backend protocol | Keep `protocol=https` (the default) |
| Backend SSL verification | Keep `healthcheck-ssl-verify=true` (the default) |
| Access control | Place an authenticating reverse proxy or WAF in front if content is not fully public |
| Rate limiting | Add rate limiting at an upstream component if abuse protection is needed |
| Cached content | Only route public, non-personalized content through the charm |
| Machine access | Restrict local user access (TLS private keys are readable by local users) |

## Source verification

Each claim must be traced to:
- `content-cache/src/nginx_manager.py` (nginx config generation)
- `content-cache/src/certificates.py` (cert storage, permissions)
- `content-cache-backends-config/config.yaml` (config defaults)
- nginx official docs where relevant
