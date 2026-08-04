# apx-caddy-stats

Copyright © Approximated Inc. All rights reserved.

No permission is granted to use, copy, modify, merge, publish, distribute,
sublicense, or sell copies of this software or any associated files without
prior written permission from the copyright holder.

## Unified build

This module now bundles stats, trace, challenge/edge-verify, and the
apx_gate reverse-proxy handler into one importable package. A build-time
`--with` line:

```
--with github.com/Approximated-Inc/apx-caddy-stats
```

replaces the three separate per-module `--with` lines previously listed in
the fleet Dockerfile (`fly/Dockerfile`) — plus a second required `--with`
for `caddy-l4`, since the mode_v2 stats core imports `layer4` directly (see
the verified build command below).

Importing the root package registers all 12 apx Caddy module IDs:

- `apx`
- `apx_stats`
- `http.handlers.apx_stats`
- `http.handlers.apx_gate`
- `apx_trace`
- `http.handlers.apx_trace`
- `http.handlers.apx_trace_mark`
- `http.reverse_proxy.transport.apx_trace`
- `apx_challenge`
- `http.handlers.apx_challenge`
- `http.handlers.apx_verify_endpoints`
- `http.handlers.apx_verify`

Use `tools/check-modules.sh <caddy-binary>` to verify a built `caddy` binary
registers all 12 IDs (exits non-zero on any miss).

**Provenance:** `trace/` was imported from apx-caddy-trace commit `bb9d7f7`;
`challenge/` was imported from apx-caddy-challenge (edge-verify) commit
`e9434a7`. Both subpackages carry their Phase-0 code verbatim — no logic
changes, only import-path and directory relocation.

**Verified build (2026-08-04):** an `xcaddy` build of Caddy v2.11.3 against
this tree (arm64, local `go1.26.1`) succeeds and passes the module gate.
The `caddy-l4` `--with` is required — the mode_v2 stats core imports
`layer4`, so a single-flag build fails to compile:

```
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
OUT=$(mktemp -d)
~/go/bin/xcaddy build v2.11.3 \
  --with github.com/Approximated-Inc/apx-caddy-stats=/Users/carter/dev/APX/apx-caddy-unified \
  --with github.com/mholt/caddy-l4=github.com/Approximated-Inc/caddy-l4@8ebffe3b63fc968cc4e0ba8fcc2ec450c94cce00 \
  --output "$OUT/caddy"

tools/check-modules.sh "$OUT/caddy"
# => all 12 apx module IDs registered
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

## apx_gate

`apx_gate` (module ID `http.handlers.apx_gate`) is a single server-level
handler that replaces two things generated configs install separately
today:

- the top-of-chain `{"handler":"apx_stats"}` handler (stats recording), and
- the shared per-request `{"handler":"geoip2","enable":"wild"}` route
  further down the inner subroute (the one whose only job is populating
  `geoip2.*` placeholders for the `Geoip-Country` header route).

It does **not** touch anything else in the per-server chain: `apx_trace`
and trace marks, the `apx_challenge`/`apx_verify` routes, the per-vhost
`waf` handler, or the vhost routes themselves (identity handlers, rewrite,
encode, reverse_proxy) are all unchanged and stay exactly where they are
today.

**Config shape:**

```json
{"handler": "apx_gate", "geo": "wild"}
```

`apx_gate` composes two apps and requires both:

- `apx_stats` — the same recording sink the `apx_stats` handler uses today
  (counters, request_event, challenge_attempt, unique-clients hashing).
- `apx` with `geo.db_path` set — the mmdb-backed geo reader used for
  lookups.

`Provision` resolves both via `AppIfConfigured` (not `ctx.App`) and hard-
errors if either is missing, rather than silently instantiating an empty
app — a silent instantiation would mean dropped counters (no `apx_stats`)
or an always-empty geo surface (no `apx`) with no error to show for it.

**Geo mode semantics:** the `geo` field mirrors the incumbent
`caddy-geoip2` fork's `Enable` values — `"wild"` (leftmost
X-Forwarded-For entry when present, else RemoteAddr), `"strict"`
(RemoteAddr only), `"trusted_proxies"` (XFF only when Caddy's
trusted-proxy var is true), or `"off"` (lookups disabled, fixed keys
resolve empty). An empty/absent `geo` field maps to **off** — deliberately
*not* the fork's implicit `trusted_proxies` default, so an unconfigured
gate behaves like a disabled geoip2 handler rather than quietly doing
lookups.

> **Note:** prod's mode is `"wild"`, which trusts the **leftmost**
> X-Forwarded-For entry — client-controlled and spoofable. That is the
> incumbent's real, shipped behavior, and it is preserved here
> byte-for-byte for compatibility. Changing it (e.g. to the rightmost XFF
> entry, or to RemoteAddr-only) would change `Geoip-Country`, geo-gated
> edge rules, and the counters' Country dimension for any client that
> sends an X-Forwarded-For header — that is an explicit, flagged product
> decision to make separately, not a side effect of adopting this handler.

**Lazy placeholder surface:** on every request, `apx_gate` registers a
lazy `geoip2.*` replacer provider that reproduces the fork's full
compatibility surface — the 89 fixed keys (blanket `""` before any lookup
runs; typed values, including zero/false/empty on a DB miss, once one
does) plus the unbounded dynamic locale- and subdivision-indexed keys —
preserving the fork's two-state typed semantics exactly (e.g.
`geoip2.country_eu` is the string `""` pre-lookup but the bool `false`
post-lookup on a miss). Nothing is computed until a specific key is read:
`geoip2.country_code` is special-cased to a fast, country-only decode path
(the perf win this handler exists for), while every other key falls back
to a one-time full record decode, memoized per request.

**Recording parity:** `apx_gate`'s `ServeHTTP` calls the exact same
`recordCompletedRequest` function the `apx_stats` handler calls (shared
code, extracted for reuse — no behavior change) — same monitor-skip check,
same response wrapper, same recording-after-`next.ServeHTTP`-returns
semantics. A shape-equivalence test harness (`gate_equivalence_test.go`)
A/B-tests this: it drives an identical request set through both the old
apx_stats+geoip2 shape and the new apx_gate shape and byte-compares
responses plus captured ingest rows, after normalizing only genuinely
volatile fields (timestamps, per-process sequence counters).

**Rollout stance:** the generator-side flag that chooses `apx_gate` over
today's two-piece shape lands in the Phoenix repo (`approximated`) on a
separate branch/PR — out of scope for this module. The old shape (a
standalone `apx_stats` handler plus a `geoip2` route) remains fully
supported here; nothing in this change removes it. Adopting the
`apx_gate` shape requires the generator to also emit the `apx` app (with
`geo.db_path`) in generated configs, which today's generated configs do
not include.

## Phase status

This branch (`apx-unified-module`) contains:

- `trace/` — apx-caddy-trace imported verbatim from commit `bb9d7f7`.
- `challenge/` — apx-caddy-challenge (edge-verify) imported verbatim from
  commit `e9434a7`.
- `unified.go` — single-import registration so one `--with
  github.com/Approximated-Inc/apx-caddy-stats` line replaces the three
  separate per-module `--with` lines in `fly/Dockerfile`.
- `tools/check-modules.sh` — gate script asserting all 12 apx module IDs
  register in a built `caddy` binary.
- `apx/` (package `apxapp`) — the `apps.apx` skeleton plus the flag-gated
  in-process config puller described above.

Both imported subpackages carry their Phase-0 code verbatim — no logic
changes, only import-path and directory relocation. Renaming this
repository/module path to `apx-caddy` is **deferred to push time** (a call
for Carter to make, along with the `fly/Dockerfile` `--with` swap and image
build — both out of scope for this branch).

**Phase 2** (the `apx_gate` handler, geo reader, and lazy geoip2 provider
described above) is complete on this branch, Go side only — the
generator-side change to emit `apx_gate` shape configs is separate,
pending work in the Phoenix repo (`approximated`).
