# apx-caddy-stats

Copyright © Approximated Inc. All rights reserved.

No permission is granted to use, copy, modify, merge, publish, distribute,
sublicense, or sell copies of this software or any associated files without
prior written permission from the copyright holder.

## Unified build

This module now bundles stats, trace, and challenge/edge-verify into one
importable package. A single build-time `--with` line:

```
--with github.com/Approximated-Inc/apx-caddy-stats
```

replaces the three separate per-module `--with` lines previously listed in
the fleet Dockerfile (`fly/Dockerfile`).

Importing the root package registers all 10 apx Caddy module IDs:

- `apx_stats`
- `http.handlers.apx_stats`
- `apx_trace`
- `http.handlers.apx_trace`
- `http.handlers.apx_trace_mark`
- `http.reverse_proxy.transport.apx_trace`
- `apx_challenge`
- `http.handlers.apx_challenge`
- `http.handlers.apx_verify_endpoints`
- `http.handlers.apx_verify`

Use `tools/check-modules.sh <caddy-binary>` to verify a built `caddy` binary
registers all 10 IDs (exits non-zero on any miss).

**Provenance:** `trace/` was imported from apx-caddy-trace commit `bb9d7f7`;
`challenge/` was imported from apx-caddy-challenge (edge-verify) commit
`e9434a7`. Both subpackages carry their Phase-0 code verbatim — no logic
changes, only import-path and directory relocation.
