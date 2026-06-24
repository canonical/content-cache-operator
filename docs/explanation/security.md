---
myst:
  html_meta:
    "description lang=en": "Explanation of the security design decisions in the Content Cache charm, including TLS, backend authentication, access control, and cached data risks."
---

(explanation_security)=

# Security

The charm makes deliberate security decisions at three boundaries: the connection from clients
to nginx, the connection from nginx to backends, and the nginx process itself. This page
explains those decisions, the gaps that operators must address externally, and the best
practices for deploying the charm securely.

## Client to charm

### Transport security

The charm supports HTTPS via the `certificates` relation using the `tls-certificates`
interface. When a certificate is issued for a hostname, nginx listens on port 443 with that
certificate and private key. Without this relation, nginx serves all traffic over HTTP on
port 80 with no encryption.

The certificate and private key for each hostname are stored together in a single PEM file at
`/etc/nginx/certs/<hostname>.pem`. The file is owned by `www-data` with permissions `0o644`,
meaning it is readable by any local user on the machine. Operators should ensure the Juju
machine is not shared with untrusted local users.

### Client authentication

The charm provides no client authentication mechanism. Any client that can reach port 80 or
443 on the machine can request cached content. This is an intentional design constraint: the
charm is built for publicly accessible static content. There are no plans to add a native
authentication feature.

### Rate limiting

The charm does not configure nginx rate limiting
([`limit_req`](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) or
[`limit_conn`](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html)). Operators
who need protection against abuse or denial-of-service attacks must add rate limiting at a
component placed in front of the charm, such as a load balancer, reverse proxy, or WAF.

## Charm to backend

### Backend protocol

The `protocol` configuration option on `content-cache-backends-config` controls whether nginx
contacts backends over HTTP or HTTPS. It defaults to `https`. Operators should keep this
default unless backends do not support HTTPS.

### Backend SSL certificate verification

The `healthcheck-ssl-verify` option on `content-cache-backends-config` controls whether the
Lua healthcheck module verifies the backend SSL certificate during health checks. It defaults
to `true`. Setting it to `false` disables certificate verification for healthchecks and should
only be used in controlled environments — for example, when backends use self-signed
certificates on a trusted private network.

This option only affects healthchecks. The nginx
[`proxy_pass`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass)
directive does not perform SSL certificate verification for backend connections. Operators who
require end-to-end SSL verification for proxied requests must configure this at the
infrastructure level (for example, by using a private CA trusted by the machine).

## Internal

### Process user

nginx worker processes run as `www-data`, a low-privilege system account. The cache directory
at `/data/nginx/cache/` and the certificate files at `/etc/nginx/certs/` are owned by
`www-data`.

### Status page access

The nginx status page at `/nginx_status` and the backend health status page at
`/nginx_backends_status` are restricted to `127.0.0.1` only. External clients cannot access
these endpoints. This is hardcoded in the generated nginx configuration and cannot be changed
via charm configuration.

### Subprocess security

The charm uses `shell=False` for all subprocess calls, preventing shell injection attacks from
malformed configuration values.

## Cached data risks

### Public-only content

The charm's cache key is based on `$scheme$proxy_host$request_uri` (the nginx default). It
does not include request headers such as `Cookie` or `Authorization`. Two requests for the
same URL with different session cookies share a single cache entry: the first response is
cached and served to every subsequent requester of that URL, regardless of their identity.

Operators must ensure that only public, non-personalized content is routed through the charm.
Routing personalized or session-dependent content through the charm will cause users to
receive each other's responses.

### No cache purge

The charm provides no built-in mechanism to purge a cached response on demand — for example,
if sensitive content was accidentally cached. Cache entries are removed when their
`proxy-cache-valid` TTL expires or when they are evicted by the 10-minute inactive timeout.
Operators who need on-demand purge capability must implement it directly at the nginx level
outside the charm, or wait for natural expiry.

## Best practices

| Practice | Recommendation |
|---|---|
| Enable TLS | Integrate with a `tls-certificates` provider charm |
| Backend protocol | Keep `protocol=https` (the default) |
| Backend SSL verification | Keep `healthcheck-ssl-verify=true` (the default) |
| Access control | Place an authenticating reverse proxy or WAF in front if the content is not fully public |
| Rate limiting | Add rate limiting at a component placed in front of the charm (load balancer, reverse proxy, or WAF) if abuse protection is needed |
| Cached content | Only route public, non-personalized content through the charm |
| Machine access | Restrict local user access to the Juju machine — TLS private keys are readable by local users |
