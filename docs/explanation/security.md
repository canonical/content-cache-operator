---
myst:
  html_meta:
    "description lang=en": "Explanation of the security design decisions in the Content Cache charm, including TLS, backend authentication, access control, and cached data risks."
---

(explanation_security)=

# Security

The charm makes deliberate security decisions across three areas: client to charm,
charm to backend, and internal process security.

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

The charm provides no client authentication mechanism. Any client that can reach the charm's HTTP(S) listener (port 80 when no `certificates` relation is present, otherwise port 443) can request cached content. This is an intentional design constraint: the charm is built for publicly accessible static content. There are no plans to add a native authentication feature.

### Rate limiting

The charm does not configure nginx rate limiting
([`limit_req`](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) or
[`limit_conn`](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html)). Operators
who need protection against abuse or denial-of-service attacks must add rate limiting at a
component placed in front of the charm, such as a load balancer, reverse proxy, or Web Application Firewall (WAF).

## Charm to backend

### Backend protocol

The `protocol` configuration option on `content-cache-backends-config` controls whether nginx
contacts backends over HTTP or HTTPS. The configuration defaults to `https`. Operators should keep this
default unless backends do not support HTTPS.

### Backend SSL certificate verification

The charm contacts backends over two separate code paths: the Lua healthcheck module (periodic
health pings) and the nginx `proxy_pass` directive (actual proxied requests). These have
different SSL verification behavior.

**Healthchecks** — the `healthcheck-ssl-verify` configuration option on `content-cache-backends-config`
controls whether the Lua healthcheck module verifies the backend SSL certificate during health
pings. The configuration defaults to `true`. Setting the configuration to `false` disables certificate verification for
healthchecks and should only be used in controlled environments, for example, when backends
use self-signed certificates on a trusted private network.

**Proxied requests** — nginx's
[`proxy_ssl_verify`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify)
defaults to `off` and the charm does not override it. This means that even when
`protocol=https`, nginx encrypts the connection to the backend but does **not** verify the
SSL certificate of the backend. Traffic to the backend is protected against passive eavesdropping
but not against a machine-in-the-middle attack on that connection. There is no charm configuration
option to enable SSL certificate verification for proxied backend connections.

## Internal

### Process user

On Ubuntu, the nginx package is configured to run worker processes as `www-data` via the
[`user` directive](https://nginx.org/en/docs/ngx_core_module.html#user) in the system
`nginx.conf`. `www-data` is a low-privilege system account with no login shell and no sudo
rights. If nginx were compromised, the attacker would have only the limited access of
`www-data` — they cannot read arbitrary files owned by other users or escalate privileges
without a separate exploit.

The charm creates and owns all cache and certificate files as `www-data`. The cache directory
at `/data/nginx/cache/` and the certificate files at `/etc/nginx/certs/` are owned by
`www-data` (set via `os.chown` in the charm code).

### Status page access

The nginx status page at `/nginx_status` and the backend health status page at
`/nginx_backends_status` are restricted to `127.0.0.1` using the nginx
[`allow`/`deny` directives](https://nginx.org/en/docs/http/ngx_http_access_module.html).
External clients cannot access these endpoints. This behavior is hard-coded in the generated nginx
configuration and cannot be changed via charm configuration.

### Subprocess security

The charm uses `shell=False` for all subprocess calls, preventing shell injection attacks from
malformed configuration values.

## Cached data risks

### Public-only content

The charm's cache key is based on the nginx default `$scheme$proxy_host$request_uri`. It
does not include request headers such as `Cookie` or `Authorization`. Two requests for the
same URL with different session cookies share a single cache entry: the first response is
cached and served to every subsequent requester of that URL, regardless of their identity.

Operators must ensure that only public, non-personalized content is routed through the charm.
Routing personalized or session-dependent content through the charm means users will
receive each other's responses.

### No cache purge

The charm provides no mechanism to purge a cached response on demand. Cache entries
are only removed when their `proxy-cache-valid` TTL expires or when nginx's inactive
eviction removes them (default: 10 minutes of no access). If sensitive content is
accidentally cached, operators must wait for natural expiry.

## Best practices

| Practice | Recommendation |
|---|---|
| TLS | Integrate with a `tls-certificates` provider charm to enable TLS |
| Backend protocol | Keep the default `protocol=https` |
| Backend SSL verification | Keep the default `healthcheck-ssl-verify=true` |
| Access control | Place an authenticating reverse proxy or WAF in front if the content is not fully public |
| Rate limiting | Add rate limiting at a component placed in front of the charm (load balancer, reverse proxy, or WAF) if abuse protection is needed |
| Cached content | Only route public, non-personalized content through the charm |
| Machine access | Restrict local user access to the Juju machine |
