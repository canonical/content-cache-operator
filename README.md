[![CharmHub Badge](https://charmhub.io/content-cache/badge.svg)](https://charmhub.io/content-cache)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

# Content Cache

A Juju charm for deploying and managing a content cache.

## Overview

A service for caching content, built on top of [HAProxy](https://www.haproxy.com/) and [Nginx](https://www.nginx.com/)
configurable to cache any http or https web site. Tuning options include
cache storage size, maximum request size to cache and cache validity duration.

This service was developed to provide front-end caching for web sites run by
Canonical's IS team, and to reduce the need for third-party CDNs by providing
high-bandwidth access to web sites via this caching front-end. Currently used
for a number of services including [the Snap Store](https://snapcraft.io/store),
the majority of Canonical's web properties including [ubuntu.com](https://ubuntu.com) and
[canonical.com](https://canonical.com), and [Ubuntu Extended Security Maintenance](https://ubuntu.com/security/esm).

See also [the Kubernetes version of this charm](https://charmhub.io/content-cache-k8s).

## Usage

To deploy the charm:

    juju deploy content-cache

For details on configuring sites, see [the sites configuration documentation](https://charmhub.io/content-cache/docs/sites-configuration).

## Metrics

To get metrics:

    juju deploy telegraf
    juju add-relation telegraf:haproxy content-cache:haproxy-statistics

You can then query the telegraf endpoint to get HAProxy metrics from the
content-cache charm.

To get cache hits metrics:

    juju config content-cache enable_prometheus_metrics=true

This will expose the following metrics for each site configured:

    # HELP nginx_cache_request_hit_total Number of cache hits per site
    # TYPE nginx_cache_request_hit_total counter
    nginx_cache_request_hit_total{host="myhost"} 10
    # HELP nginx_cache_request_total Number of cache requests per site 
    # TYPE nginx_cache_request_total counter                           
    nginx_cache_request_total{host="myhost"} 20
    # HELP nginx_http_request_total Number of HTTP requests per site
    # TYPE nginx_http_request_total counter
    nginx_http_request_total{host="myhost",status="200"} 110129
    # HELP nginx_metric_errors_total Number of nginx-lua-prometheus errors
    # TYPE nginx_metric_errors_total counter
    nginx_metric_errors_total 0

---

For further details, [see here](https://charmhub.io/content-cache/docs).
