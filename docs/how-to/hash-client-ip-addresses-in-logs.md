---
myst:
  html_meta:
    "description lang=en": "Learn how to enable salted hashing of client IP addresses in the Content Cache charm access logs."
---

(how_to_hash_client_ip_addresses_in_logs)=

# How to hash client IP addresses in logs

Use the `client-ip-hash-salt` configuration option to enable salted hashing of client IP
addresses in the content-cache charm's access and cache logs. Hashing client IP addresses
helps protect user privacy in logs; see {ref}`Security <explanation_security>` for details.

## Enable client IP hashing

This feature hashes client IP addresses using SHA-256 combined with a salt that you provide
through a Juju secret. Generate a random salt with sufficient entropy, for example using
`openssl`:

```shell
openssl rand -hex 32
```

Create a secret containing a `salt` key, and grant the `content-cache` application access to
it.

```shell
juju add-secret client-ip-hash-salt salt=<salt-value>
juju grant-secret client-ip-hash-salt content-cache
```

The `add-secret` command prints the secret's URI. Set the charm configuration to that URI to
enable hashing.

```shell
juju config content-cache client-ip-hash-salt=<secret-uri>
```

The salt must be a non-empty string. It must not contain control characters, the DEL
character, double quotes (`"`), backslashes (`\`), or dollar signs (`$`); the charm enters a
blocked state if the secret contains any of these characters.

## Disable client IP hashing

Remove the configuration option to restore plaintext client IP logging.

```shell
juju config content-cache --reset client-ip-hash-salt
```

## Rotate the salt

Update the secret's content to rotate the salt.

```shell
juju update-secret client-ip-hash-salt salt=<new-salt-value>
```

```{note}
Secret revisions are supported, but rotating the salt changes the hash produced for a given
client IP address. Logs recorded before the rotation cannot be correlated with logs recorded
afterwards.
```

## Verify client IP hashing is applied

Send a request to content-cache using the unit's public address and allocated port:

```shell
CONTENT_CACHE_IP=$(juju status --format json | jq -r '.applications."content-cache".units."content-cache/0"."public-address"')
curl http://$CONTENT_CACHE_IP:30000
```

Then inspect the cache log:

```shell
juju ssh content-cache/0 -- sudo tail -1 /var/log/nginx/content-cache_0/30000.cache.log
```

Before enabling hashing, the client IP address appears in plaintext in the `client_address`
field.

```{terminal}
:output-only:

{"time": "2026-09-22T18:15:42+00:00", "connection_number": "1374", "hostname": "juju-33f0f5-5", "client_address": "10.94.111.1", "request_method": "GET", ...}
```

After enabling hashing with a configured salt, the same field contains the salted SHA-256
hash instead.

```{terminal}
:output-only:

{"time": "2026-09-22T18:16:02+00:00", "connection_number": "1401", "hostname": "juju-33f0f5-5", "client_address": "5bd1f203b50928cfec3f9ceb925bdb55b9c1c059aa0361471464ed5632497f2", "request_method": "GET", ...}
```

This hashed value also replaces the client IP address in the combined access log.
