(how_to_enable_cos)=

# How to enable COS

The charm utilizes Nginx as a static web content cache.
Various metrics on the requests to the cache are logged.
The logs can be ingested into [Canonical Observability Stack (COS)](https://charmhub.io/topics/canonical-observability-stack) or [COS Lite](https://charmhub.io/topics/canonical-observability-stack/editions/lite) by integrating the charm with a charm that provides `cos-agent` integration.

The [Grafana Agent charm](https://charmhub.io/grafana-agent) provides `cos-agent` integration to machine charms.
If you are new to COS or the Grafana Agent charm it is recommended to first follow [this guide](https://charmhub.io/grafana-agent/docs/using) to understand the concepts of COS and how the charms work together.

With a working Content Cache charm deployment name `cache`, the following will add COS support to it:

```bash
juju deploy grafana-agent cos-agent
juju integrate cos-agent cache
```

Then the Grafana Agent charm should be integrated with your COS instance.
Once integrated a Grafana dashboard named "Content Cache" should be imported. The metrics of content cache should appear in the dashboard.

## Available metrics

These metrics are only available once the `cos-agent` integration is active.

The charm ships a Grafana dashboard that is populated from the per-hostname JSON access logs
forwarded to Loki. The following panels are available:

| Panel | Description |
|---|---|
| Status Codes | Count of responses by HTTP status class (2xx, 3xx, 4xx, 5xx) |
| Response Time | Average and maximum response time across requests |
| Requests Status | Total request rate and failed request rate over time |
| Failed Requests % | Percentage of requests that returned a 4xx or 5xx status |
| Bandwidth | Total bytes sent and bytes served from cache hits over time |
| Bandwidth Saved % | Percentage of outbound bandwidth served from cache rather than the upstream backend |
| Cache Hits | Total request count compared to cache hit count over time |
| Cache Hit % | Percentage of requests served directly from the cache |

Each panel can be filtered by Juju unit and hostname.

The following fields are recorded per request in the access log and are available for custom
Loki queries:

| Field | Description |
|---|---|
| `time` | Request timestamp (ISO 8601) |
| `connection_number` | nginx connection ID |
| `hostname` | Hostname of the virtual server that handled the request |
| `client_address` | Client IP address |
| `request_method` | HTTP method (GET, HEAD, etc.) |
| `protocol` | HTTP protocol version |
| `status_code` | HTTP response status code |
| `cache_status` | nginx cache result: `HIT`, `MISS`, `EXPIRED`, `BYPASS`, etc. |
| `request_time` | Total time to serve the request in seconds |
| `bytes_sent` | Total bytes sent to the client |
| `body_bytes_sent` | Response body bytes sent (excluding headers) |

### Disk usage

The Grafana Agent also runs a built-in node exporter that collects filesystem metrics for all
mounted filesystems on the machine, including `node_filesystem_avail_bytes` and
`node_filesystem_size_bytes`. These appear in the standard Node Exporter Grafana dashboard.

The charm does not declare Juju storage, so `/data/nginx/cache/` is a directory on the root
filesystem by default. Cache disk usage is not separately visible in node_exporter metrics
unless the operator manually mounts a separate volume at `/data/nginx/cache/` at the OS level
before deploying.