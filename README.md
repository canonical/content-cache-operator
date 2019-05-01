# Overview

Deploy your own content distribution network (CDN).

# Usage

To deploy the charm:

    juju deploy cs:content-cache

Set juju config for the `site` option as required. For example:

    # Site with some public, some authenticated content, using another site
    # with two IPs for authentication. In this case, 10.1.1.2 and 10.1.1.3
    # would need to listen on 443 for auth.example1.com and process
    # authentication requests.
    example1.com:
      tls-cert-bundle-path: /var/lib/haproxy
      locations:
        '/':
          extra-config:
            - root /srv/example1.com/content/
            - autoindex on
        '/auth':
          modifier: '='
          backends:
            - 10.1.1.2:443
            - 10.1.1.3:443
          backend-check-path: /status
          backend-path: /auth-check/
          backend-tls: True
          cache-validity: '200 401 1h'
          origin-headers:
            - Original-URI: $request_uri
            - Resource-Name: example1
          extra-config:
            - internal
            - proxy_cache_key $http_authorization
          site-name: auth.example1.com
        '/status':
          extra-config:
            - stub_status on
        '/private/content/':
          extra-config:
            - root /srv/example1.com/content/
            - autoindex on
            - auth_request /auth
          nagios-expect: 401 Unauthorized

To get metrics:

    juju deploy cs:telegraf
    juju add-relation telegraf:haproxy content-cache:haproxy-statistics

You can then query the telegraf endpoint to get HAProxy metrics from the
content-cache charm.
