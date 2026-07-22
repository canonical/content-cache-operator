(how_to_enable_https)=

# How to connect to HTTPS backends

The Content Cache charm can proxy to backends over HTTPS by setting the `protocol` option
on the `content-cache-backends-config` charm.

```bash
juju config backends protocol=https
```

When `protocol=https`, nginx connects to the backend IP addresses over TLS on port 443.

## Skipping SSL certificate verification

If the backends use self-signed certificates, you must disable SSL verification for the
healthcheck probes, otherwise all backends will be marked as down:

```bash
juju config backends healthcheck-ssl-verify=false
```

## TLS termination for incoming traffic

The Content Cache charm does not terminate TLS for incoming client requests.
Client-facing TLS termination is expected to be handled by an upstream ingress component,
such as haproxy configured with the `ingress-configurator` charm.
