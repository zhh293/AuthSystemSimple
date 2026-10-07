# SSO monitoring templates

These are deployment templates, not an applied production configuration.

## Prometheus

Run Prometheus with environment expansion enabled, for example with `--config.expand-env`, and set `SSO_METRICS_TARGET` to the private management address and port reachable from the Prometheus process, such as `sso-server.internal:8081`. Mount `prometheus.yml` as the main configuration and `sso-alerts.yml` at `/etc/prometheus/rules/sso-alerts.yml`.

The SSO management server binds to `127.0.0.1:8081` by default. For a remote scraper, set `SSO_MANAGEMENT_ADDRESS` to a private interface address and restrict that port to the monitoring network with host/network policy. The endpoint has no application authentication; never expose it publicly. If Prometheus shares the SSO host, keep the loopback bind and target `127.0.0.1:8081`.

## Grafana

Import `sso-overview-dashboard.json` and select the Prometheus data source in its `Prometheus` variable. It shows authentication outcomes, refresh-family events, TGC validation, HTTP rates/P95, and logout revocation failures.

Alert thresholds are starter values: authentication failure ratio above 50% with at least 20 attempts, endpoint P95 above one second, and prompt signals for refresh replay, authentication/TGC/resource-token dependency failures, directory synchronization failures, or a down scrape target. Tune these against production traffic, SLOs, and response procedures before paging. Metric labels are intentionally bounded and contain no user or token identifiers.
