> **Note:** This package was imported into `apx-caddy-stats` (the unified apx module) as of 2026-08-03. Do not build it standalone — use the single `--with github.com/Approximated-Inc/apx-caddy-stats` line documented in the root README's "Unified build" section. The instructions below are preserved from the standalone repo for historical reference.

# apx-caddy-trace

Header-gated request trace plugin for Approximated's Caddy cluster. Dormant on customer traffic; emits structured events to Redis streams when a valid trace token is present.

See `docs/superpowers/specs/2026-04-21-virtual-host-debug-requests-design.md` in the `approximated` repo for the full design.
