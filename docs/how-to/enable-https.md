(how_to_enable_https)=

# How to connect to HTTPS backends

The Content Cache charm can proxy to backends over HTTPS by using HTTPS URLs in the `backends` option
on the `content-cache-backends-config` charm.

```bash
juju config backends backends=https://10.10.1.1:443
```

When the URL scheme is `https`, nginx connects to the backend over TLS on the specified port.

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
