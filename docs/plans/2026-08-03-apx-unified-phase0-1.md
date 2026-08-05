# apx Unified Caddy Module — Phase 0+1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate apx-caddy-stats, apx-caddy-trace, and apx-caddy-challenge into one Go module (this repo, branch `apx-unified-module`) with zero behavior change, then add the `apps.apx` app skeleton with a flag-gated in-process config puller.

**Architecture:** apx-caddy-stats is the consolidation base (largest module). trace and challenge come in as subtree-merged subpackages (`trace/`, `challenge/`) keeping their own package names and ALL Caddy module IDs unchanged. A root blank-import file makes a single `xcaddy --with` line register everything. Phase 1 adds a new `apx/` package: an `apps.apx` Caddy app owning cross-reload state via `caddy.UsagePool`, containing a config puller (disabled by default) that replicates fly/maybepull.sh+pullscript.sh semantics in-process.

**Tech Stack:** Go 1.26.1, Caddy v2.11.3, testify, zap. Build tool: xcaddy.

## Global Constraints

- Working dir: `/Users/carter/dev/APX/apx-caddy-unified` (git worktree of apx-caddy-stats, branch `apx-unified-module`). NEVER touch `~/dev/APX/apx-caddy-stats`, `~/dev/APX/apx-caddy-trace`, `~/dev/APX/apx-caddy-challenge` working trees — they are other sessions' checkouts; read them via `git -C <repo> show main:<file>` or the subtree commands given below.
- ALL Caddy module IDs must remain byte-identical: `apx_stats`, `http.handlers.apx_stats`, `apx_trace`, `http.handlers.apx_trace`, `http.handlers.apx_trace_mark`, `http.reverse_proxy.transport.apx_trace`, `apx_challenge`, `http.handlers.apx_challenge`, `http.handlers.apx_verify_endpoints`, `http.handlers.apx_verify`.
- Zero wire-format changes: NDJSON rows to Phoenix, challenge HMAC token format, trace token format all unchanged. Phase 0 tasks copy code verbatim — no refactors, no renames, no "improvements" while moving.
- Package names stay: root `apxstats`, `trace/` = `apxtrace`, `challenge/` = `apxchallenge`. New Phase-1 package: `apx/` = `apxapp`.
- Commit messages: conventional style, NO Co-Authored-By lines, no emoji.
- Gate for every task: `go build ./... && go vet ./... && go test ./...` from repo root, all green.

---

### Task 1: Subtree-import apx-caddy-trace as `trace/`

**Files:**
- Create: `trace/` (entire apx-caddy-trace tree at its `main` tip, bb9d7f7) via git subtree
- Delete after import: `trace/go.mod`, `trace/go.sum`, `trace/.github/` (if present)
- Modify: `go.mod` (merge trace's direct deps)

**Interfaces:**
- Produces: package `apxtrace` importable as `github.com/Approximated-Inc/apx-caddy-stats/trace`; registers `apx_trace`, `http.handlers.apx_trace`, `http.handlers.apx_trace_mark`, `http.reverse_proxy.transport.apx_trace` via its init().

- [ ] **Step 1: Subtree add (preserves history)**

```bash
cd /Users/carter/dev/APX/apx-caddy-unified
git subtree add --prefix=trace /Users/carter/dev/APX/apx-caddy-trace main
```
Expected: merge commit "Add 'trace/' from commit ..." with trace files under `trace/`.

- [ ] **Step 2: Remove nested module files; check for self-imports**

```bash
git rm -f trace/go.mod trace/go.sum 2>/dev/null; git rm -rf trace/.github 2>/dev/null
grep -rn "Approximated-Inc/apx-caddy-trace" trace/ || echo "no self-imports"
```
If self-imports exist, rewrite them to `github.com/Approximated-Inc/apx-caddy-stats/trace` with sed and show the diff.

- [ ] **Step 3: Merge deps + build + test**

```bash
go mod tidy
go build ./... && go vet ./... && go test ./trace/... && go test ./...
```
Expected: all green. `go mod tidy` picks up trace's deps (caddy, zap, testify already shared). If tidy changes go.sum only, that's expected.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: import apx-caddy-trace as trace/ subpackage (from bb9d7f7, module IDs unchanged)"
```

---

### Task 2: Subtree-import apx-caddy-challenge as `challenge/`

**Files:**
- Create: `challenge/` (apx-caddy-challenge at its `main` tip, e9434a7) via git subtree
- Delete after import: `challenge/go.mod`, `challenge/go.sum`, `challenge/.github/` (if present), any `challenge/caddy` binary artifacts
- Modify: `go.mod`

**Interfaces:**
- Produces: package `apxchallenge` importable as `github.com/Approximated-Inc/apx-caddy-stats/challenge`; registers `apx_challenge`, `http.handlers.apx_challenge`, `http.handlers.apx_verify_endpoints`, `http.handlers.apx_verify`.

- [ ] **Step 1: Subtree add**

```bash
cd /Users/carter/dev/APX/apx-caddy-unified
git subtree add --prefix=challenge /Users/carter/dev/APX/apx-caddy-challenge main
```

- [ ] **Step 2: Clean nested module files; check self-imports and embedded assets**

```bash
git rm -f challenge/go.mod challenge/go.sum 2>/dev/null; git rm -rf challenge/.github 2>/dev/null
ls challenge/  # if a stray `caddy` binary or build artifact came in, git rm it
grep -rn "Approximated-Inc/apx-caddy-challenge" challenge/ || echo "no self-imports"
grep -rn "go:embed" challenge/ # verify embed paths are relative (they are: assets/) — nothing to change, just confirm
```

- [ ] **Step 3: Build + test**

```bash
go mod tidy && go build ./... && go vet ./... && go test ./challenge/... && go test ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: import apx-caddy-challenge as challenge/ subpackage (from e9434a7, module IDs unchanged)"
```

---

### Task 3: Root registration shim + module-ID gate script

**Files:**
- Create: `unified.go` (repo root)
- Create: `tools/check-modules.sh`
- Modify: `README.md` (add "Unified build" section)

**Interfaces:**
- Consumes: subpackages from Tasks 1–2.
- Produces: single-import registration — `xcaddy --with github.com/Approximated-Inc/apx-caddy-stats` registers all 10 module IDs. `tools/check-modules.sh <caddy-binary>` exits non-zero if any ID is missing.

- [ ] **Step 1: Write unified.go**

```go
// Package apxstats is the unified Approximated Caddy module. Importing it
// registers the stats, trace, and challenge modules; subpackages register
// themselves via their init functions.
package apxstats

import (
	_ "github.com/Approximated-Inc/apx-caddy-stats/challenge"
	_ "github.com/Approximated-Inc/apx-caddy-stats/trace"
)
```

- [ ] **Step 2: Write tools/check-modules.sh**

```bash
#!/usr/bin/env bash
# Verifies a caddy binary registers every apx module ID. Usage: check-modules.sh ./caddy
set -euo pipefail
BIN="${1:?usage: check-modules.sh <caddy-binary>}"
IDS=(apx_stats http.handlers.apx_stats apx_trace http.handlers.apx_trace \
     http.handlers.apx_trace_mark http.reverse_proxy.transport.apx_trace \
     apx_challenge http.handlers.apx_challenge http.handlers.apx_verify_endpoints \
     http.handlers.apx_verify)
LIST="$("$BIN" list-modules 2>/dev/null)"
rc=0
for id in "${IDS[@]}"; do
  if ! grep -qx "$id" <<<"$LIST"; then echo "MISSING: $id"; rc=1; fi
done
[ $rc -eq 0 ] && echo "all ${#IDS[@]} apx module IDs registered"
exit $rc
```

`chmod +x tools/check-modules.sh`

- [ ] **Step 3: Full gate**

```bash
go build ./... && go vet ./... && go test ./...
```

- [ ] **Step 4: README section** — add under a `## Unified build` heading: the single `--with` line replaces the three per-module lines in fly/Dockerfile; list the 10 module IDs; note trace/ and challenge/ provenance commits (bb9d7f7, e9434a7) and that Phase-0 code is verbatim.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: single-import registration for unified module + module-ID gate script"
```

---

### Task 4: xcaddy build parity gate

**Files:**
- Create: none committed (binary goes to a temp dir)
- Modify: `README.md` (record verified build command)

**Interfaces:**
- Consumes: Task 3's unified.go + check-modules.sh.

- [ ] **Step 1: Install xcaddy and build against the local tree**

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
cd /Users/carter/dev/APX/apx-caddy-unified
OUT=$(mktemp -d)
~/go/bin/xcaddy build v2.11.3 \
  --with github.com/Approximated-Inc/apx-caddy-stats=/Users/carter/dev/APX/apx-caddy-unified \
  --output "$OUT/caddy"
```
Expected: build succeeds (arm64 local build is fine for the gate; the fleet image builds amd64 separately).

- [ ] **Step 2: Run the module-ID gate**

```bash
tools/check-modules.sh "$OUT/caddy"
```
Expected: `all 10 apx module IDs registered`.

- [ ] **Step 3: Commit README note**

```bash
git add README.md && git commit -m "docs: record verified unified xcaddy build + module gate"
```

---

### Task 5: `apps.apx` app skeleton (Phase 1)

**Files:**
- Create: `apx/app.go`, `apx/app_test.go`
- Modify: `unified.go` (add blank import of `apx/`)

**Interfaces:**
- Produces: Caddy app module ID `apx`, package `apxapp`. Config JSON shape: `{"puller": {"enabled": false, "interval_seconds": 60}}`. Exposes `func (a *App) PullerRunning() bool` for tests and later wiring. Cross-reload state via package-level `caddy.NewUsagePool()` keyed `"apx.state"` holding `*SharedState{ LastAppliedConfigStamp string }`.

- [ ] **Step 1: Write failing test `apx/app_test.go`**

```go
package apxapp

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/stretchr/testify/require"
)

func TestAppProvisionDefaults(t *testing.T) {
	var a App
	require.NoError(t, json.Unmarshal([]byte(`{}`), &a))
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	require.NoError(t, a.Provision(ctx))
	require.False(t, a.Puller.Enabled)
	require.Equal(t, 60, a.Puller.IntervalSeconds)
	require.NoError(t, a.Start())
	require.False(t, a.PullerRunning()) // disabled by default
	require.NoError(t, a.Stop())
}

func TestSharedStateSurvivesReload(t *testing.T) {
	// two apps provisioned sequentially (simulating config reload) see the same SharedState
	s1, err := loadSharedState()
	require.NoError(t, err)
	s1.SetLastStamp("123")
	s2, err := loadSharedState()
	require.NoError(t, err)
	require.Equal(t, "123", s2.LastStamp())
}

func TestCaddytestLoadsApp(t *testing.T) {
	caddytest.Default.AdminPort = 2999
	tester := caddytest.NewTester(t)
	tester.InitServer(`{ "admin": {"listen": "localhost:2999"}, "apps": {"apx": {"puller": {"enabled": false}}} }`, "json")
}
```

(Adjust `caddy.NewContext` usage to the v2.11.3 test-context idiom if it differs — `caddy.Context{Context: context.Background()}` + `caddy.NewContext` is the pattern used by caddy's own module tests; if `caddytest` port conflicts locally, guard the third test with `-short` skip.)

- [ ] **Step 2: Run tests, verify failure** — `go test ./apx/...` fails: package doesn't exist.

- [ ] **Step 3: Implement `apx/app.go`**

```go
// Package apxapp provides the apps.apx Caddy app: the process-wide home for
// Approximated background machinery (config puller now; stats flush, defense
// rules feed, geo reader in later phases). State that must survive config
// reloads lives in a caddy.UsagePool, mirroring coraza-caddy's wafPool.
package apxapp

import (
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() { caddy.RegisterModule(App{}) }

type PullerConfig struct {
	Enabled         bool   `json:"enabled,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	// CheckURL/DownloadURL/ProxyServerID/InternalKey default from the
	// CALL_HOME_URL, PROXY_SERVER_ID, APX_INTERNAL_KEY env vars at
	// Provision time so generated configs stay secret-free.
	CheckURL      string `json:"check_url,omitempty"`
	DownloadURL   string `json:"download_url,omitempty"`
	ProxyServerID string `json:"proxy_server_id,omitempty"`
	AdminEndpoint string `json:"admin_endpoint,omitempty"` // default http://127.0.0.1:2019/load
}

type App struct {
	Puller PullerConfig `json:"puller,omitempty"`

	logger *zap.Logger
	state  *SharedState
	puller *puller // nil unless enabled
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "apx",
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)
	if a.Puller.IntervalSeconds <= 0 {
		a.Puller.IntervalSeconds = 60
	}
	st, err := loadSharedState()
	if err != nil {
		return fmt.Errorf("apx: loading shared state: %w", err)
	}
	a.state = st
	return nil
}

func (a *App) Start() error {
	if a.Puller.Enabled {
		p, err := newPuller(a.Puller, a.state, a.logger)
		if err != nil {
			return fmt.Errorf("apx: puller: %w", err)
		}
		a.puller = p
		a.puller.start()
	}
	return nil
}

func (a *App) Stop() error {
	if a.puller != nil {
		a.puller.stop()
		a.puller = nil
	}
	return nil
}

func (a *App) PullerRunning() bool { return a.puller != nil && a.puller.running() }

// --- cross-reload shared state ---

var statePool = caddy.NewUsagePool()

type SharedState struct {
	mu        sync.Mutex
	lastStamp string
}

func (s *SharedState) Destruct() error { return nil }

func (s *SharedState) SetLastStamp(v string) { s.mu.Lock(); s.lastStamp = v; s.mu.Unlock() }
func (s *SharedState) LastStamp() string     { s.mu.Lock(); defer s.mu.Unlock(); return s.lastStamp }

func loadSharedState() (*SharedState, error) {
	val, _, err := statePool.LoadOrNew("apx.state", func() (caddy.Destructor, error) {
		return new(SharedState), nil
	})
	if err != nil {
		return nil, err
	}
	return val.(*SharedState), nil
}
```

Also add a minimal `apx/puller.go` stub so this compiles (Task 6 replaces it):

```go
package apxapp

import "go.uber.org/zap"

type puller struct{ started bool }

func newPuller(cfg PullerConfig, st *SharedState, log *zap.Logger) (*puller, error) {
	return &puller{}, nil
}
func (p *puller) start()        { p.started = true }
func (p *puller) stop()         { p.started = false }
func (p *puller) running() bool { return p != nil && p.started }
```

And in `unified.go` add `_ "github.com/Approximated-Inc/apx-caddy-stats/apx"` to the import block. Add `apx` to the IDS list in `tools/check-modules.sh`.

- [ ] **Step 4: Run tests** — `go test ./apx/... && go test ./...` green.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(apx): apps.apx skeleton with UsagePool-backed shared state and puller flag"
```

---

### Task 6: Config puller (flag-gated, replicates maybepull+pullscript)

**Files:**
- Create: `apx/puller.go` (replacing the Task-5 stub), `apx/puller_test.go`

**Interfaces:**
- Consumes: `PullerConfig`, `SharedState`, from Task 5 (exact names above).
- Produces: `newPuller(cfg PullerConfig, st *SharedState, log *zap.Logger) (*puller, error)`; `start()/stop()/running()`. Behavior contract below.

**Behavior contract (mirrors fly/maybepull.sh + fly/pullscript.sh):**
1. Every interval (with ±10% jitter): GET `{CheckURL}/{ProxyServerID}/{lastStamp}` with header `apx-internal-key: {InternalKey}`. `lastStamp` starts empty → send `0`.
2. On HTTP 200 (= cloud is newer): GET `{DownloadURL}/{ProxyServerID}` with header `apx-key: {InternalKey}`, response is a zip; extract `caddyconfig.json` (in memory, `archive/zip` over a `bytes.Reader`; reject entries >32MB or names containing `/` traversal).
3. POST the JSON to `AdminEndpoint` with `Content-Type: application/json`. 2xx → parse the config's stamp: reuse maybepull semantics by GETting `http://127.0.0.1:80/last-updated` is NOT available in tests — instead store the stamp returned in the config-check response header `x-apx-config-stamp` if present, else current unix time, via `st.SetLastStamp`.
4. Any failure at any step: log at WARN with a step tag (download/unzip/load), do NOT crash, retry next tick. Consecutive-failure counter; after 5 consecutive failures log at ERROR once.
5. `stop()` cancels the loop context and waits for the goroutine (sync.WaitGroup) — must be reload-safe (old app Stop before/after new app Start is fine because state is in the pool, and two pullers briefly overlapping must not corrupt state — lastStamp writes are mutex-guarded).
6. Env fallback in `newPuller`: if `cfg.CheckURL == ""` use `os.Getenv("CALL_HOME_URL") + "/api/config-check"`; DownloadURL → `CALL_HOME_URL + "/api/proxy-cluster/download-fly-config"`; ProxyServerID → `PROXY_SERVER_ID` env; InternalKey → `APX_INTERNAL_KEY` env; AdminEndpoint → `http://127.0.0.1:2019/load`. Error if enabled and ProxyServerID or key resolve empty.
7. HTTP client: one `http.Client` with 20s timeout, keep-alives ON (this is the whole point vs curl).

- [ ] **Step 1: Write failing tests `apx/puller_test.go`** — use `httptest.NewServer` for control plane (mux: config-check path returns 204 then 200; download path returns an in-memory zip containing `caddyconfig.json`) and a second httptest server standing in for the admin endpoint recording the POSTed body. Tests:

```go
package apxapp

// build an in-memory zip with one caddyconfig.json entry
func mkZip(t *testing.T, name, content string) []byte { /* archive/zip into bytes.Buffer */ }

func TestPullerNoopOn204(t *testing.T)            {}
func TestPullerPullsAndLoadsOn200(t *testing.T)   {} // asserts admin server received exact JSON, stamp stored
func TestPullerBadZipDoesNotCrash(t *testing.T)   {} // download returns garbage; next tick still runs
func TestPullerAdminRejectLogged(t *testing.T)    {} // admin returns 400; lastStamp NOT updated
func TestPullerStopIsClean(t *testing.T)          {} // start, stop, assert goroutine exited (WaitGroup + timeout)
func TestPullerMissingCredsFailsFast(t *testing.T){} // enabled + no env/config -> newPuller error
```

Write the real bodies (poll interval 10ms in tests via an unexported `tickInterval` override field on puller). Run: `go test ./apx/...` → FAIL (stub puller).

- [ ] **Step 2: Implement `apx/puller.go`** per the contract. Structure: `type puller struct { cfg PullerConfig; st *SharedState; log *zap.Logger; client *http.Client; cancel context.CancelFunc; wg sync.WaitGroup; tick time.Duration; consecFails int; startedMu sync.Mutex; started bool }`. Loop: `for { select ctx.Done / time.After(jitter(tick)) }` → `checkOnce(ctx)`.

- [ ] **Step 3: `go test ./apx/... -race` green; then full `go test ./... && go vet ./...`.**

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat(apx): in-process config puller (flag-gated) replicating maybepull/pullscript semantics"
```

---

### Task 7: Final gate + docs

**Files:**
- Modify: `README.md` (apx app section: config shape, env vars, puller rollout note — puller ships DISABLED; cron path stays as fallback until a full release train proves it)

- [ ] **Step 1: Full suite** — `go build ./... && go vet ./... && go test ./... -race` all green.
- [ ] **Step 2: Rebuild via xcaddy + `tools/check-modules.sh` (now expects 11 IDs incl. `apx`).**
- [ ] **Step 3: README updates; commit** — `git add -A && git commit -m "docs: apx app usage, puller rollout notes, phase 0+1 summary"`.

---

## Out of scope (later phases, do NOT start)
- fly/Dockerfile single `--with` swap + image build (needs amd64 + Carter's push approval)
- Renaming the repo/module path to apx-caddy (Carter's call at push time)
- apx_gate handler, host dispatch, rules feed, geo reader (Phases 2+, design scratchpad #107)
