# How to enable COS integration

The charm utilizes nginx as a static web content cache.
Various metrics on the requests to the cache are logged.
The logs can be ingested into [COS](https://charmhub.io/topics/canonical-observability-stack) or [COS Lite](https://charmhub.io/topics/canonical-observability-stack/editions/lite) by integrating the charm with a charm that provides `cos-agent` integration.

The [Grafana Agent charm](https://charmhub.io/grafana-agent) provides `cos-agent` integration to machine charms.
If you are new to COS or the Grafana Agent charm it is recommended to first follow [this guide](https://charmhub.io/grafana-agent/docs/using) to understand the concepts of COS and how the charms work together.

With a working Content Cache charm deployment name `cache`, the following will add COS support to it:

```bash
juju deploy grafana-agent cos-agent
juju integrate cos-agent cache
```

Then the Grafana Agent charm should be integrated with your COS instance.
