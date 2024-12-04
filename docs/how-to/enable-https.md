# How to enable HTTPS

In order for the Content Cache charm to take HTTPS requests, the charm will need TLS certificates.
The charm can request and receive certificates from charms that provides tls-certificates.

For example, with a working content-cache charm deployment name `cache`, the following will add self-signed TLS certificates to it:

```bash
juju deploy self-signed-certificates cert
juju integrate cert cache
```

After the charm are in active status, cURL can be used to test the charm. Note the `-k` since self-signed certificates are used.

```bash
curl http://<IP of the juju machine> -H "Host: <hostname in config>" -k
```
