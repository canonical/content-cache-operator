# Overview

Deploy your own content distribution network (CDN).


# Usage

To deploy the charm:

    juju deploy cs:content-cache

Set juju config for the `site` option as required. For example:

# Test 1: The basic port and backends (HTTP)
site1.local:
  port: 80
  locations:
    /:
      backends:
        - 127.0.1.10:80
        - 127.0.1.11:80
        - 127.0.1.12:80
      signed-url-hmac-key: SOMEHMACKEY
      origin-headers:
        - X-Origin-Key: SOMEXORIGINKEY
        - X-Some-Header-1: something one two three
        - X-Some-Header-2: something:one:two:three

# Test 2: TLS/SSL as well as backends (HTTPS)
site2.local:
  tls-cert-bundle-path: /etc/haproxy/some-bundle.crt
  locations:
    /:
      backend-tls: True
      backend-check-method: GET
      backend-check-path: /check/
      backends:
        - 127.0.1.10:443
        - 127.0.1.11:443
        - 127.0.1.12:443
    /my-local-content/:
      extra-config:
        - root /var/www/html
    /my-local-content2/:
      extra-config:
        - root /var/www/html

# Test 3: No port, just backends (HTTP)
site3.local:
  locations:
    /:
      backends:
        - 127.0.1.10:80
        - 127.0.1.11:80
        - 127.0.1.12:80
      backend-options:
        - forwardfor except 127.0.0.1
        - forceclose

# Test 4: No backends, a few local content
site4.local:
  locations:
    /:
      extra-config:
        - autoindex on
    /ubuntu/pool/:
      extra-config:
        - autoindex on
        - auth_request /auth

# Test 5: Multiple backends
site5:
  site-name: site5.local
  locations:
    /:
      backends:
        - 127.0.1.10:80
    /auth:
      modifier: '='
      backends:
        - 127.0.1.11:80
      backend-path: /auth-check/
      cache-validity: '200 401 1h'
