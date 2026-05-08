# apx-caddy-stats

Caddy v2 module that aggregates per-vhost request counters in memory and
periodically POSTs them to the Approximated app's analytics ingest
endpoint (`/api/internal/analytics/ingest`).

Per-request work is allocation-light: classify the response origin, look
up or insert one map entry, atomic-add five integer counters and one
histogram bucket. No per-request allocation, no per-request HTTP traffic
to the app.

The full pipeline (counter shape, retention tiers, percentile math,
storage adapter, dashboard surfacing) lives in the
[approximated](../approximated) repo under
`docs/superpowers/specs/2026-04-…-vhost-cluster-analytics-design.md`.

## Modules registered

| Caddy module ID | Purpose |
|-----------------|---------|
| `apx_stats` | Top-level App: owns the counter map, flush goroutine, HTTP shipper, HMAC secret. One per Caddy process. |
| `http.handlers.apx_stats` | HTTP middleware: classifies origin, increments counters per request. Installed once at the top of the global handler chain. |

## Build

Built into the production Caddy image alongside the other custom modules
via `xcaddy`:

```dockerfile
RUN xcaddy build v2.11.2 \
    ... existing modules ... \
    --with github.com/Approximated-Inc/apx-caddy-stats@<sha>
```
