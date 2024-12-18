# Grafana dashboard

The Content Cache charm supports metric collection with COS integration and visualization of metrics with grafana dashboard.
For details see `docs/how-to/setup-grafana-dashboard.md`.

## Development

The development of dashboard can be done by designing the dashboard in grafana then export the "JSON Model" under "Dashboard settings".
The exported JSON file need to have the `uid` of the loki data source replaced with `${lokids}` for it to be importable in a different grafana instance.
Use the `replace_loki_uid.py` helper script in this directory to do this.
