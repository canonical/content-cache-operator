(how_to_enable_https)=

# How to connect to HTTPS backends

The Content Cache charm can proxy to backends over HTTPS by using HTTPS URLs in the `backends` option
on the `content-cache-backends-config` charm.
The following example sets the backend to `https://10.10.1.1:443`:

```bash
juju config content-cache-backends-config backends=https://10.10.1.1:443
```

When the URL scheme is `https`, nginx connects to the backend over TLS on the specified port
(which is `443` in the example above).

## Provide a CA certificate

To verify the backend TLS certificate, integrate a certificate provider charm (such as
`self-signed-certificates` or `lego`) using the `receive-ca-cert` endpoint:

```bash
juju integrate <cert-provider>:send-ca-cert content-cache:receive-ca-cert
```

Once the CA certificate is received, the content-cache charm will:

- Write the certificate to `/etc/nginx/certs/ca-bundle.pem`
- Configure nginx to verify backend certificates against this CA
- Use `proxy_ssl_verify on` and `proxy_ssl_server_name off` (SNI is disabled in this
  version)

If HTTPS backends are configured but no CA certificate has been provided, the charm will enter
`WaitingStatus` until the `receive-ca-cert` relation is established.

Multiple `receive-ca-cert` providers are supported; all provided CA certificates are merged
into a single bundle.

## Skip SSL certificate verification for health checks

If the backends use self-signed certificates, you must disable SSL verification for the
healthcheck probes, or all backends will be marked as down. To disable SSL verification, run:

```bash
juju config backends healthcheck-ssl-verify=false
```

## TLS termination for incoming traffic

When HAProxy connects to the content-cache over HTTPS, the charm must present a TLS
certificate. This is configured through the `certificates` relation
(interface: `tls-certificates`).

Deploy a TLS certificate provider (e.g. `lego`) as `cache-lego` and integrate:

```bash
juju integrate content-cache:certificates cache-lego:certificates
```

When the certificate is issued, the charm automatically:

1. Writes the combined cert+key PEM to `/etc/nginx/certs/<unit-ip>.pem`
2. Reconfigures nginx to listen with `ssl` on the allocated port
3. Updates the `cache-backends` relation data to return `https://` URLs

HAProxy must trust this certificate. Integrate HAProxy with `cache-lego` using the
`certificate_transfer` interface:

```bash
juju integrate cache-lego:send-ca-cert haproxy:receive-ca-cert
```

If the `certificates` relation is present but the certificate has not yet been issued,
the charm enters `WaitingStatus`. If the relation is removed, the charm automatically deletes the
cert file and reverts nginx to HTTP.
