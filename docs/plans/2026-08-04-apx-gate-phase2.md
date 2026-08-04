# apx_gate (Phase 2, Go side) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `apx_gate` HTTP handler that can replace the server-level `apx_stats` + shared `geoip2` handlers with identical observable behavior, so a later generator flag can swap the config shape per cluster.

**Architecture:** `apx_gate` lives in the ROOT package `apxstats` (direct access to the existing unexported recording internals — zero wire-format risk). It: (1) does the monitor skip, (2) wraps the ResponseWriter with the existing `recorder`, (3) registers a LAZY replacer provider for the full `geoip2.*` placeholder surface backed by a geo reader owned by the `apps.apx` app, (4) calls `next`, (5) runs the exact same post-chain recording as today's `apx_stats` handler via a shared function extracted by refactor. Trace, trace marks, challenge, waf, and all per-vhost handlers are untouched and remain in the inner chain.

**Normative appendix:** `.superpowers/sdd/phase2-facts.md` (505 lines, exact contracts with file:line refs). Every task brief references specific sections. Where this plan and the facts file disagree, the facts file wins.

**Tech Stack:** Go 1.26.1, Caddy v2.11.3, oschwald/maxminddb-golang, testify.

## Global Constraints

- Working dir `/Users/carter/dev/APX/apx-caddy-unified`, branch `apx-unified-module`. Gate: `go build ./... && go vet ./... && go test ./... -race` green before every commit.
- ZERO observable-behavior change vs today's handlers (facts §1, §3): wire formats byte-identical (field order is the Phoenix contract), var/header/placeholder names exact, servErr returned unchanged, monitor dual-value skip semantics (`r.Header.Get("apx-monitor") == "true"`), hijack/flush/push delegation.
- Geo semantics preserved EXACTLY: `wild` mode = leftmost XFF entry split on `", "` (including the no-space quirk), else RemoteAddr host; parse failure → empty placeholders (facts §3b, implication 5). ASN placeholder `geoip2.autonomous_system_number` does not exist (only `traits_…`); Key.ASN stays structurally 0 (implication 6).
- The full `geoip2.*` fixed-key surface (facts §3a list) must resolve with ok=true and "" default on every request whether or not a lookup happens; dynamic locale/subdivision keys resolve when a lookup succeeded (lazy provider may compute on demand).
- mmdb missing/corrupt → empty placeholders, no error, no crash (implication 7). Reader opened at Provision (reopen per config load — matches today's freshness coupling).
- No changes to: trace/, challenge/, existing handler.go BEHAVIOR (refactor extraction allowed, all existing tests must pass unmodified except import-level mechanics), wire encoders, app.go recording machinery semantics.
- Conventional commits, NO Co-Authored-By.

---

### Task 1: Extract the shared post-chain recording path (pure refactor)

**Files:** Modify `handler.go` only. Test: existing suite (unchanged) is the gate.

**Interfaces produced:** `func (h *statsRecorderCore) …` OR (simpler, chosen) package-level `func recordCompletedRequest(app *App, logger *zap.Logger, rec *recorder, r *http.Request, servErr error, start time.Time)` containing EVERYTHING `(h Handler) record(...)` does today (counter row, request_event mode_v2, challenge_attempt, edge-verify attempt if present in this tree, uniques hash) — moved verbatim, with the existing `Handler.record` becoming a thin call to it. Also export-internally the entry-skip check as `func monitorSkip(r *http.Request) bool` (the `apx-monitor == "true"` Get check).

**Steps:**
- [ ] Move the body of the existing record path into `recordCompletedRequest` verbatim (mechanical cut/paste + parameter threading; NO logic edits — resist every cleanup temptation).
- [ ] `Handler.ServeHTTP` now calls `monitorSkip` + `recordCompletedRequest`. Diff of behavior: none.
- [ ] Full suite green (`go test ./... -race`). Existing handler tests are the spec — they must pass UNMODIFIED.
- [ ] Commit: `refactor(stats): extract recordCompletedRequest for reuse by apx_gate (no behavior change)`

### Task 2: Geo reader owned by apps.apx

**Files:** Create `apx/geo.go`, `apx/geo_test.go`, `apx/testdata/GeoLite2-City-Test.mmdb` (copy the canonical small test DB from oschwald/maxminddb-golang's test-data; if licensing/pathing is awkward, generate a tiny City-shaped mmdb in a test helper using github.com/maxmind/mmdbwriter as a TEST-ONLY dependency). Modify `apx/app.go` (config + lifecycle).

**Interfaces produced (consumed by Task 3/4):**
```go
type GeoConfig struct { DBPath string `json:"db_path,omitempty"` } // App gains Geo GeoConfig `json:"geo,omitempty"`
// on *App:
func (a *App) GeoCountryCode(ip net.IP) string          // fast path: decode only country.iso_code; "" on any failure
func (a *App) GeoRecord(ip net.IP) (*geoRecord, bool)   // full City decode for exotic placeholder keys; cached nothing (caller caches per request)
```
`geoRecord` mirrors the fork's record struct field-for-field (facts §3a consumer surface). Reader: `maxminddb.Open(DBPath)` at Provision when DBPath != "" ; nil-safe on missing/corrupt (log WARN once, all lookups return zero values); closed in Stop… **NO**: closed in Cleanup/Destruct via the caddy module lifecycle — mmap must outlive Stop only until the new config's app provisions; simplest correct: close in `Stop()` AFTER the new app is running is not knowable — mirror geoip2_state behavior (never closed, GC'd) BUT we can do better safely: close in `Destruct` of a UsagePool entry keyed by DBPath+inode… **Decision locked: match today's behavior — open at Provision, never explicitly close (finalizer-free, mmap released on process exit / GC), documented.** This matches the incumbent module exactly and avoids use-after-close during reload overlap.
- [ ] Tests: country fast path returns expected ISO for a test-DB IP; missing file → "" + no panic; corrupt file → "" + no panic; full record decode for city name; `-race` with concurrent lookups.
- [ ] Commit: `feat(apx): geo reader (country fast path + lazy full decode) on apps.apx`

### Task 3: Lazy geoip2.* replacer provider

**Files:** Create `geoprovider.go` (root package apxstats), `geoprovider_test.go`.

**Interfaces produced:** `func newGeoProvider(app *apxapp.App, mode string, r *http.Request) func(key string) (any, bool)` returning a Caddy replacer Map provider that:
- Handles ONLY keys with prefix `geoip2.`.
- Computes client IP once per request per facts §3b (`wild`: leftmost XFF via `strings.Split(fwdFor, ", ")[0]` else RemoteAddr host; `strict`: RemoteAddr; `trusted_proxies`: XFF only when Caddy trusted-proxy var true; `off|false|0`: no lookup).
- `geoip2.ip_address` → the looked-up IP string or "".
- `geoip2.country_code` → `App.GeoCountryCode` fast path (memoized per request).
- Every other FIXED key from facts §3a → "" until a full `GeoRecord` decode is triggered (memoized), then the fork's exact value mapping (same stringification: bools as Go `strconv.FormatBool`-equivalent to the fork's `repl.Set` types — replicate the fork's typed Set values: the provider may return the same typed `any`).
- Dynamic keys (`…_names_<locale>`, `subdivisions_<n>_…`) resolve after full decode; unknown geoip2.* keys → ("", true) to preserve the fork's blanket-init observable behavior… **verify against fork: unlisted keys were NEVER initialized → GetString returns ok=false today. Provider must return (nil,false) for geoip2.* keys not in the fixed list and not dynamic-derivable. The fixed list is closed — transcribe it from facts §3a verbatim into a package-level map.**
- [ ] Tests: fixed keys resolve ("",true) with no DB; country_code correct with test DB; leftmost-XFF quirk (incl. `a, b` vs `a,b` non-split), RemoteAddr fallback; unknown key → false; full-decode trigger only on exotic key access (assert via lookup-count instrumentation on a test hook).
- [ ] Commit: `feat(gate): lazy geoip2 placeholder provider (full fork surface, decode on demand)`

### Task 4: The apx_gate handler

**Files:** Create `gate.go`, `gate_test.go` (root package apxstats). Modify `unified.go` (nothing — same package), `tools/check-modules.sh` (add `http.handlers.apx_gate` → 12 IDs).

**Module:** ID `http.handlers.apx_gate`, JSON config `{"handler":"apx_gate","geo":"wild"}` (field `Geo string` — mirrors the fork's Enable values; empty = "off" → provider still registered serving fixed-empty keys, matching a disabled geoip2 handler's placeholder-init behavior).

**ServeHTTP order (facts implications 1,2,8,9,10,11):**
1. `monitorSkip(r)` → `next.ServeHTTP(w, r)` unchanged (no wrap, no provider — matches today: apx_stats skips wrapping; geoip2 route still initialized placeholders TODAY on monitor requests… **check facts §2a: geoip2 runs on route [11] for ALL requests including monitors. So on monitor-skip the gate MUST STILL register the provider (cheap, lazy) to keep placeholder resolvability for monitor traffic; it skips only recording.** Locked: provider always registered; recording skipped on monitorSkip.)
2. Register geo provider on the request's replacer (`r.Context().Value(caddy.ReplacerCtxKey)` → `repl.Map(provider)`).
3. Wrap `w` in `recorder{status: 200}` (the existing struct).
4. `servErr := next.ServeHTTP(wrapped, r)`.
5. `recordCompletedRequest(app, logger, wrapped, r, servErr, start)`.
6. `return servErr` — UNCHANGED (implication 2).

Provision: resolves `*App` (stats app) via `ctx.App("apx_stats")` and `*apxapp.App` via `ctx.App("apx")`; error if either missing (gate requires both apps configured — the generator will guarantee this).
- [ ] Tests (behavioral, against a caddytest or handler-level harness): counter+request_event recorded identically to Handler for: served proxy request (200), HandlerError 429 → rate_limited disposition, error containing "interruption triggered" → waf_blocked, no-vhost terminal challenge (vhost_id=0 + Host + challenge_attempt row), hijacked connection, monitor skip records nothing but `{geoip2.country_code}` still resolves in an inner handler, servErr passthrough asserted.
- [ ] Commit: `feat(gate): apx_gate handler — stats recording + lazy geo at server level`

### Task 5: Registration gate + xcaddy proof

- [ ] `tools/check-modules.sh` 12 IDs; xcaddy build v2.11.3 with BOTH `--with` flags (unified module + `github.com/mholt/caddy-l4=github.com/Approximated-Inc/caddy-l4@8ebffe3b63fc968cc4e0ba8fcc2ec450c94cce00` — required since the mode_v2 stats core imports layer4, see progress ledger); run gate → "all 12 apx module IDs registered".
- [ ] Commit: `feat: register apx_gate (12th module ID) + build gate update`

### Task 6: Shape-equivalence harness

**Files:** Create `gate_equivalence_test.go` (root).

Two caddytest configs derived from the cluster-32 server shape (facts §2a, §8): (A) today's shape — `apx_stats` ⊃ subroute[`apx_trace`, inner[geoip2 route, Geoip-Country header route, vars/headers/static_response vhost routes]]; (B) gate shape — `apx_gate` ⊃ subroute[`apx_trace`, inner[Geoip-Country header route (same `{geoip2.country_code}` placeholder), same vhost routes]] — geoip2 handler route REMOVED. Both point their apx_stats app ingest at an in-test HTTP server capturing NDJSON.
- [ ] Drive identical request sets through both (plain GET on a vhost host; XFF-carrying request; monitor request; unknown-host request) and assert: identical response headers (incl. Geoip-Country), and captured NDJSON rows identical modulo ts/machine_seq/duration fields (normalize those, byte-compare the rest).
- [ ] Commit: `test(gate): shape-equivalence harness old-vs-gate config`

### Task 7: Docs + ledger

- [ ] README "## apx_gate" section: what it replaces, config shape, the two-app dependency, geo mode semantics + the deliberate wild-mode preservation note, rollout stance (generator flag lands in the Phoenix repo; old shape remains supported).
- [ ] Commit: `docs: apx_gate usage and rollout notes`

## Out of scope
- Elixir generator changes (approximated repo — separate branch/PR).
- Absorbing trace marks/challenge/waf; host dispatch + vhost map (Phase 3); rules feed (Phase 5).
- Changing geo client-IP semantics or populating real ASN (explicit product decisions, flagged in README).
