# apx-caddy-trace

Header-gated request trace plugin for Approximated's Caddy cluster. Dormant on customer traffic; emits structured events to Redis streams when a valid trace token is present.

See `docs/superpowers/specs/2026-04-21-virtual-host-debug-requests-design.md` in the `approximated` repo for the full design.
