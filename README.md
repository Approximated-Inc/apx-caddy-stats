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

Importing the root package registers all 11 apx Caddy module IDs:

- `apx`
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
registers all 11 IDs (exits non-zero on any miss).

**Provenance:** `trace/` was imported from apx-caddy-trace commit `bb9d7f7`;
`challenge/` was imported from apx-caddy-challenge (edge-verify) commit
`e9434a7`. Both subpackages carry their Phase-0 code verbatim — no logic
changes, only import-path and directory relocation.

**Verified build (2026-08-03):** an `xcaddy` build of Caddy v2.11.3 against
this tree (arm64, local `go1.26.1`) succeeds and passes the module gate:

```
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
OUT=$(mktemp -d)
~/go/bin/xcaddy build v2.11.3 \
  --with github.com/Approximated-Inc/apx-caddy-stats=/Users/carter/dev/APX/apx-caddy-unified \
  --output "$OUT/caddy"

tools/check-modules.sh "$OUT/caddy"
# => all 11 apx module IDs registered
```

`xcaddy` resolves the module's own `go.mod` pin of `caddy/v2 v2.11.2` up to
`v2.11.3` for the build automatically (`go get github.com/caddyserver/caddy/v2@v2.11.3`)
— no manual go.mod changes were needed.

## apps.apx

`apps.apx` (Go package `apxapp`, module ID `apx`) is the process-wide home
for Approximated background machinery that doesn't belong to a single HTTP
handler. Today that's the in-process config puller; later phases add a
stats flush loop, a defense-rules feed, and a geo reader. State that must
survive Caddy config reloads (e.g. the last-seen config stamp) lives in a
`caddy.UsagePool`, the same pattern coraza-caddy uses for its WAF pool.

Enable it by adding an `apx` entry under `apps` in the Caddy JSON config:

```json
{
  "apps": {
    "apx": {
      "puller": {
        "enabled": false,
        "interval_seconds": 60
      }
    }
  }
}
```

`puller.enabled` and `puller.interval_seconds` (default `60`) are the only
fields normally set in generated configs. `check_url`, `download_url`,
`proxy_server_id`, and `admin_endpoint` are also configurable but exist
mainly for tests — in production they default from environment variables
at puller-start time (never re-read per tick):

- `CALL_HOME_URL` — base URL; the puller appends `/api/config-check` and
  `/api/proxy-cluster/download-fly-config` to it.
- `PROXY_SERVER_ID` — this cluster's proxy server id, used in both the
  check and download URL paths.
- `APX_INTERNAL_KEY` — sent as the `apx-internal-key` (check) / `apx-key`
  (download) header. Deliberately **not** a config field, so generated
  Caddy configs stay secret-free.

If `puller.enabled` is true and either `PROXY_SERVER_ID` or
`APX_INTERNAL_KEY` is unavailable (neither a config field nor the env var
set), `Start()` returns an error.

**Stamp/status semantics**, mirroring the fleet's `maybepull.sh` +
`pullscript.sh`:

- The puller GETs `<check_url>/<proxy_server_id>/<last_stamp>` on every
  tick (jittered ±10% around `interval_seconds` to avoid fleet-wide
  sync-hammering).
- **HTTP 200** means a newer config exists; the plain-text response body is
  the new stamp (an integer unix timestamp — preferred over the legacy
  `x-apx-config-stamp` header). The puller downloads the zipped config,
  extracts `caddyconfig.json` in memory (path-traversal and 32 MiB entry
  caps enforced), and POSTs it to the Caddy admin endpoint
  (`admin_endpoint`, default `http://127.0.0.1:2019/load`). On success the
  new stamp is stored in the `caddy.UsagePool`-backed shared state so it
  survives the next config reload.
- **HTTP 204/304** means the cluster is already up to date; no download
  happens.
- **Any other status** (401/400/5xx, transport errors, download/unzip/load
  failures) counts as a failure: logged at WARN with a running
  consecutive-failure count, escalating to a single ERROR log at 5
  consecutive failures. No failure crashes or restarts the Caddy process —
  everything just retries next tick.

**Rollout stance:** the puller ships **disabled by default**
(`puller.enabled: false`, and the app is a no-op unless explicitly
configured). The fleet's existing cron-based `maybepull.sh` path remains
the authoritative config-sync mechanism until a full release train
validates the in-process puller in production. Turning the puller on is a
**per-cluster config decision**, made by setting `puller.enabled: true` in
that cluster's generated Caddy config — not a blanket flip for the fleet.

## Phase 0+1 status

This branch (`apx-unified-module`) contains:

- `trace/` — apx-caddy-trace imported verbatim from commit `bb9d7f7`.
- `challenge/` — apx-caddy-challenge (edge-verify) imported verbatim from
  commit `e9434a7`.
- `unified.go` — single-import registration so one `--with
  github.com/Approximated-Inc/apx-caddy-stats` line replaces the three
  separate per-module `--with` lines in `fly/Dockerfile`.
- `tools/check-modules.sh` — gate script asserting all 11 apx module IDs
  register in a built `caddy` binary.
- `apx/` (package `apxapp`) — the `apps.apx` skeleton plus the flag-gated
  in-process config puller described above.

Both imported subpackages carry their Phase-0 code verbatim — no logic
changes, only import-path and directory relocation. Renaming this
repository/module path to `apx-caddy` is **deferred to push time** (a call
for Carter to make, along with the `fly/Dockerfile` `--with` swap and image
build — both out of scope for this branch).
