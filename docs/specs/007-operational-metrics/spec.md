# SDD 007: Authentication Metrics

## Problem

The SSO service needs operational signals for authentication volume, TGC validation, logout, and refresh-token family lifecycle. Operators must be able to detect failures and replay events without collecting credentials or user identifiers as metric labels.

## Requirements

- Export counters for login outcomes (`success`, `failure`, `throttled`, `dependency_error`), TGC validation (`active`, `inactive`, `account_disabled`, `dependency_error`), logout requests and remote-dependency failures, and refresh-family events (`family_created`, `rotated`, `replay_rejected`, `invalid_rejected`).
- Export internal resource-token validation outcomes (`active`, `inactive`, `dependency_error`).
- Export directory account synchronization outcomes (`page_applied`, `failure`, `conflict`) using bounded labels and never expose source cursors or account identifiers.
- Record request counts and latency histograms for a fixed allowlist of login, authorization, token, revocation, JWKS, UserInfo, and logout endpoints; use only the normalized endpoint name and bounded status class as labels.
- Metric labels must be bounded enums. Never attach usernames, subjects, IP addresses, client IDs, token values, cookies, state, or correlation IDs.
- Expose Prometheus scraping on the management server, separate from the public protocol port and bound to loopback by default.
- Keep health probes available and document that a non-loopback management bind requires private-network controls because the scrape endpoint has no application-level authentication.
- Supply Prometheus scrape, alert-rule, and Grafana dashboard templates. Deployment-specific target routing, alert calibration against service SLOs, and restore/failover exercises remain operational acceptance work.

## Acceptance criteria

- Each listed event increments its corresponding counter without adding sensitive or high-cardinality tags.
- `/actuator/prometheus` is enabled only on the separately configured management port; the default bind address is `127.0.0.1`.
- Monitoring can distinguish login failures, throttling, inactive TGCs, refresh rotation, and replay rejection.
- Monitoring can distinguish logout attempts from logout requests whose server-side revocation could not be confirmed.
- Request metric labels never contain path parameters or raw request paths; latency histograms support operational P95/P99 calculation.
