package apxstats

// Task 6: config shape-equivalence harness.
//
// Proves that the apx_gate server shape produces observably identical
// behavior to today's fleet shape, driving the SAME request set through
// two caddytest-loaded configs modeled on the real cluster-32 srv0
// structure (phase2-facts.md §2a) with the real per-vhost route tail
// identity handlers (§8), and byte-comparing responses plus the captured
// ingest NDJSON after normalizing volatile fields.
//
//	Shape A (today):  route = apx_stats ⊃ subroute[apx_trace ⊃ subroute[
//	                    monitor/automation sanitizers, vhost routes, catch-all]]
//	Shape B (gate):   route = apx_gate(geo:"wild") ⊃ subroute[apx_trace ⊃ subroute[
//	                    sanitizers, Geoip-Country header route ({geoip2.country_code}),
//	                    same vhost routes, catch-all]]
//
// Prod-only pieces that cannot run in-test are simplified IDENTICALLY in
// both shapes: no layer4/proxy_protocol (the server listens directly, so
// client_ip is 127.0.0.1 instead of the PROXY-decoded IP), no waf/coraza,
// no challenge routes, and static_response instead of reverse_proxy
// upstreams (origin classifies as "cluster" in both shapes).
//
// SCOPING DECISION — geo is NOT part of the A/B equality claim:
// the incumbent geoip2 handler (fork Approximated-Inc/caddy-geoip2) is a
// separate repo and is not compiled into this test binary, so Shape A
// cannot run the real `{"handler":"geoip2","enable":"wild"}` route.
// Shape A therefore omits geo entirely (no geoip2 route, no Geoip-Country
// header route — including the header route with no provider would stamp
// the literal placeholder text, which is NOT what prod does). The
// equivalence claim for the geo placeholder surface itself rides on the
// geoprovider fork-mapping unit tests (geoprovider_test.go); THIS harness
// asserts Shape B's geo VALUE correctness end-to-end instead of A/B geo
// equality:
//   - the Geoip-Country request header resolves to the real country
//     ("GB" for 81.2.69.142 in the test mmdb) through the gate's lazy
//     provider + the prod-shaped headers route, observed via a
//     static_response body echo of {http.request.header.Geoip-Country};
//   - the counter rows' country dimension carries that same value.
//
// Two mechanical consequences of the seam are normalized with exact
// arithmetic (not blanket-masked):
//   - Shape B's requests carry one extra request header at record time
//     (Geoip-Country, set by the inner route BEFORE the vhost routes), so
//     B's bytes_in is higher by exactly len("Geoip-Country")+4+len(value)
//     per request (requestBytes counts "Name: Value\r\n").
//   - Shape B's echoed body is longer by len(value) (bytes_out; only
//     non-zero for the geo-divergent request).
//
// Normalized (volatile) fields, everything else byte-compared:
//   - counter rows: ts (minute bucket), duration_us_sum, lat_bNN
//     histogram keys; rows merged across minute buckets after ts removal
//     so a minute-boundary straddle can't split rows in one shape only.
//   - request_event rows: ts, ts_ms, duration_us, machine_seq.
//   - uniques rows: ts; client_hashes compared as a count for the
//     RemoteAddr-hashed request (ephemeral port makes the hash run-
//     specific) and EXACTLY for XFF-hashed requests (deterministic).
//
// The catch-all / vhost-less request (unknown.test) must produce NO rows
// in either shape: readVhostID fails on the catch-all's vhost_id="" and
// there is no challenge outcome, so both the counter and the mode_v2
// request_event paths drop it (facts §1c; implication 11's "still records"
// case is terminal challenges only, covered by the handler unit tests).
// The harness asserts that absence on both sides.
//
// caddytest note: one in-process Caddy serves the whole test binary, so
// both shapes share ONE admin port (2998 — distinct from apx/app_test.go's
// 2999, which runs in a separate `go test` process) and are loaded
// sequentially via /load. A trailing cleanup unloads the apps so the
// stats flush loop stops before the capture servers close.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/stretchr/testify/require"
)

const (
	eqAdminPort = 2998
	eqHTTPPort  = 12621

	eqUserAgent   = "apx-gate-equivalence/1.0"
	eqProxyID     = uint64(32)
	eqMachineID   = "eq-test-machine"
	eqHashSalt    = "gate-equivalence-salt"
	eqIngestToken = "gate-equivalence-token"

	// Request-set hosts → vhost ids (all counter/request_event/uniques
	// rows are keyed by these).
	eqHostA    = "site-a.test" // vhost 101: plain GET + the monitor probe
	eqHostB    = "site-b.test" // vhost 102: XFF-carrying request
	eqHostGeo  = "site-geo.test"
	eqVhostA   = uint64(101)
	eqVhostB   = uint64(102)
	eqVhostGeo = uint64(103)

	// XFF values. Geo mode "wild" reads the LEFTMOST entry; forwarded_ip
	// and the uniques hash read the RIGHTMOST. 198.51.100.7 / 203.0.113.9
	// are absent from the test mmdb (country ""), 81.2.69.142 is GB.
	eqXffB   = "198.51.100.7, 203.0.113.9"
	eqXffGeo = "81.2.69.142"

	eqGeoHeader = "Geoip-Country"
)

// eqExpectedGeoB is Shape B's expected Geoip-Country header value per
// vhost — drives both the value-correctness assertions and the exact
// bytes_in/bytes_out normalization arithmetic.
var eqExpectedGeoB = map[uint64]string{
	eqVhostA:   "",   // no XFF → RemoteAddr 127.0.0.1 → not in test mmdb
	eqVhostB:   "",   // leftmost XFF 198.51.100.7 → not in test mmdb
	eqVhostGeo: "GB", // leftmost XFF 81.2.69.142 → GB in test mmdb
}

// eqGeoBytesInDelta is the exact requestBytes contribution of the
// Geoip-Country request header Shape B's inner route adds before the
// vhost routes run: "Name: Value\r\n" = len(name)+2+len(value)+2.
func eqGeoBytesInDelta(cc string) uint64 { return uint64(len(eqGeoHeader)) + 4 + uint64(len(cc)) }

func eqVhostRoute(host string, id uint64) string {
	ids := strconv.FormatUint(id, 10)
	return `{"match":[{"host":["` + host + `"]}],"handle":[` +
		`{"handler":"vars","vhost_id":"` + ids + `"},` +
		`{"handler":"headers","request":{"set":{"X-Apx-Vhost-Id":["` + ids + `"]}}},` +
		`{"handler":"static_response","status_code":200,"body":"` + host + ` geo=[{http.request.header.Geoip-Country}]"}` +
		`],"terminal":true,"@id":"vhost_` + ids + `"}`
}

// eqSanitizerPair mirrors caddy_config_files.ex monitor_header_sanitizer_routes/1
// (facts §2a): strip a spoofed header, or normalize the secret-bearing one
// back to the exact "true" sentinel.
func eqSanitizerPair(header, secret string) string {
	return `{"match":[{"not":[{"header":{"` + header + `":["` + secret + `"]}}],"header":{"` + header + `":["*"]}}],` +
		`"handle":[{"handler":"headers","request":{"delete":["` + header + `"]}}],"terminal":false},` +
		`{"match":[{"header":{"` + header + `":["` + secret + `"]}}],` +
		`"handle":[{"handler":"headers","request":{"set":{"` + header + `":["true"]}}}],"terminal":false}`
}

// eqConfig renders the full Caddy JSON for one shape. gate=false is
// today's shape (apx_stats outer handler, no geo anywhere); gate=true is
// the apx_gate shape (geo:"wild", apps.apx with the test mmdb, and the
// prod route-[11] Geoip-Country header route minus its geoip2 handler).
func eqConfig(gate bool, ingestURL, traceSinkURL, mmdbPath string) string {
	outer := `{"handler":"apx_stats"}`
	geoHeaderRoute := ""
	apxApp := ""
	if gate {
		outer = `{"handler":"apx_gate","geo":"wild"}`
		geoHeaderRoute = `{"handle":[{"handler":"headers","request":{"set":{"` + eqGeoHeader + `":["{geoip2.country_code}"]}}}]},`
		apxApp = `"apx":{"geo":{"db_path":` + strconv.Quote(mmdbPath) + `}},`
	}

	inner := eqSanitizerPair("apx-monitor", "monitor-secret") + `,` +
		eqSanitizerPair("apx-automation", "automation-secret") + `,` +
		geoHeaderRoute +
		eqVhostRoute(eqHostA, eqVhostA) + `,` +
		eqVhostRoute(eqHostB, eqVhostB) + `,` +
		eqVhostRoute(eqHostGeo, eqVhostGeo) + `,` +
		// Catch-all: prod tail with vhost_id="" (facts §8) — traffic here
		// must NOT be counter- or request_event-recorded.
		`{"match":[],"handle":[` +
		`{"handler":"vars","vhost_id":""},` +
		`{"handler":"headers","request":{"set":{"X-Apx-Vhost-Id":[""]}}},` +
		`{"handler":"static_response","status_code":404,"body":"no-vhost geo=[{http.request.header.Geoip-Country}]"}` +
		`],"terminal":true}`

	// Nesting per facts §2a: outer handler ⊃ subroute[apx_trace ⊃ subroute[inner]].
	route := `{"match":[{}],"handle":[` + outer + `,` +
		`{"handler":"subroute","routes":[{"match":[{}],"handle":[` +
		`{"handler":"apx_trace"},` +
		`{"handler":"subroute","routes":[` + inner + `]}` +
		`]}]}]}`

	return `{
	  "admin": {"listen": "localhost:` + strconv.Itoa(eqAdminPort) + `"},
	  "apps": {
	    ` + apxApp + `
	    "apx_stats": {
	      "proxy_server_id": ` + strconv.FormatUint(eqProxyID, 10) + `,
	      "machine_id": "` + eqMachineID + `",
	      "hash_salt": "` + eqHashSalt + `",
	      "ingest": {
	        "url": ` + strconv.Quote(ingestURL) + `,
	        "auth_token": "` + eqIngestToken + `",
	        "flush_interval_ms": 200,
	        "max_retries": 1,
	        "shutdown_max_retries": 1,
	        "request_events": {"enabled": true, "mode_v2": true}
	      }
	    },
	    "apx_trace": {"event_sink": {"url": ` + strconv.Quote(traceSinkURL) + `}},
	    "http": {
	      "grace_period": "1s",
	      "servers": {
	        "srv0": {
	          "listen": ["127.0.0.1:` + strconv.Itoa(eqHTTPPort) + `"],
	          "automatic_https": {"disable": true},
	          "routes": [` + route + `]
	        }
	      }
	    }
	  }
	}`
}

type eqResponse struct {
	status  int
	body    string
	headers http.Header
}

// eqDrive sends the shared request set and returns one eqResponse per
// request, Date header stripped. Index layout:
//
//	[0] GET site-a.test        (plain vhost hit)
//	[1] GET site-b.test  + XFF (rightmost=forwarded_ip, leftmost=geo, both non-mmdb)
//	[2] GET unknown.test       (catch-all — must record nothing)
//	[3] GET site-a.test  + apx-monitor: true (entry skip — must record nothing)
//	[4] GET site-geo.test + XFF 81.2.69.142 (geo-divergent by scoping)
func eqDrive(t *testing.T) []eqResponse {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()

	do := func(host string, hdrs map[string]string) eqResponse {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", eqHTTPPort), nil)
		require.NoError(t, err)
		req.Host = host
		req.Header.Set("User-Agent", eqUserAgent)
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		h := res.Header.Clone()
		h.Del("Date")
		return eqResponse{status: res.StatusCode, body: string(body), headers: h}
	}

	return []eqResponse{
		do(eqHostA, nil),
		do(eqHostB, map[string]string{"X-Forwarded-For": eqXffB}),
		do("unknown.test", nil),
		do(eqHostA, map[string]string{"apx-monitor": "true"}),
		do(eqHostGeo, map[string]string{"X-Forwarded-For": eqXffGeo}),
	}
}

func eqFlatten(posts []capturedPost) []map[string]any {
	var rows []map[string]any
	for _, p := range posts {
		rows = append(rows, p.rows...)
	}
	return rows
}

func eqRowsOfType(rows []map[string]any, typ string) []map[string]any {
	var out []map[string]any
	for _, r := range rows {
		if r["_type"] == typ {
			out = append(out, r)
		}
	}
	return out
}

func eqU64(t *testing.T, m map[string]any, key string) uint64 {
	t.Helper()
	f, ok := m[key].(float64)
	require.True(t, ok, "row field %q missing or non-numeric in %v", key, m)
	return uint64(f)
}

// eqWaitRows deadline-polls the capture getter until the expected row
// population is present, then keeps polling until the total row count is
// stable across three consecutive checks (so late flushes — including
// anything recorded by a straggling flush tick — are in before the
// absence assertions run). No bare sleeps: every wait is a bounded poll
// against observed capture state.
func eqWaitRows(t *testing.T, get func() []capturedPost) []map[string]any {
	t.Helper()
	settled := func(rows []map[string]any) bool {
		reqEvents := len(eqRowsOfType(rows, "request_event"))
		var counterSum uint64
		for _, c := range eqRowsOfType(rows, "counter") {
			counterSum += eqU64(t, c, "request_count")
		}
		uniqVhosts := map[uint64]bool{}
		for _, u := range eqRowsOfType(rows, "uniques") {
			uniqVhosts[eqU64(t, u, "vhost_id")] = true
		}
		return reqEvents == 3 && counterSum == 3 && len(uniqVhosts) == 3
	}

	deadline := time.Now().Add(15 * time.Second)
	for !settled(eqFlatten(get())) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for expected ingest rows; have: %v", eqFlatten(get()))
		}
		time.Sleep(25 * time.Millisecond)
	}
	// Stability window: 3 consecutive equal counts, 150ms apart (covers
	// >2 flush intervals at flush_interval_ms=200).
	stable, last := 0, len(eqFlatten(get()))
	for stable < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("row count never stabilized (last %d)", last)
		}
		time.Sleep(150 * time.Millisecond)
		if n := len(eqFlatten(get())); n == last {
			stable++
		} else {
			stable, last = 0, n
		}
	}
	return eqFlatten(get())
}

// counter identity minus the ts minute bucket and minus country (asserted
// separately — see the scoping header) so rows merge deterministically.
type eqCounterID struct {
	vhost  uint64
	method string
	status uint64
	origin string
	asn    uint64
}

type eqCounterAgg struct {
	count    uint64
	bytesIn  uint64
	bytesOut uint64
}

// eqCounters merges counter rows across minute buckets and returns the
// aggregate map plus the per-vhost country values seen. A vhost showing
// two different countries fails (the request set is built so each vhost
// has exactly one).
func eqCounters(t *testing.T, rows []map[string]any) (map[eqCounterID]eqCounterAgg, map[uint64]string) {
	t.Helper()
	agg := map[eqCounterID]eqCounterAgg{}
	countries := map[uint64]string{}
	for _, r := range eqRowsOfType(rows, "counter") {
		require.Equal(t, float64(eqProxyID), r["proxy_server_id"])
		id := eqCounterID{
			vhost:  eqU64(t, r, "vhost_id"),
			method: r["method"].(string),
			status: eqU64(t, r, "status"),
			origin: r["origin"].(string),
			asn:    eqU64(t, r, "asn"),
		}
		country := r["country"].(string)
		if prev, seen := countries[id.vhost]; seen {
			require.Equal(t, prev, country, "vhost %d counter rows disagree on country", id.vhost)
		}
		countries[id.vhost] = country
		a := agg[id]
		a.count += eqU64(t, r, "request_count")
		a.bytesIn += eqU64(t, r, "bytes_in")
		a.bytesOut += eqU64(t, r, "bytes_out")
		agg[id] = a
	}
	return agg, countries
}

// eqNormalizeRequestEvents strips volatile fields and (for Shape B)
// reverses the exact byte contribution of the Geoip-Country header/echo,
// returning rows sorted by vhost_id for a field-for-field compare.
func eqNormalizeRequestEvents(t *testing.T, rows []map[string]any, geoByVhost map[uint64]string) []map[string]any {
	t.Helper()
	events := eqRowsOfType(rows, "request_event")
	out := make([]map[string]any, 0, len(events))
	for _, r := range events {
		n := make(map[string]any, len(r))
		for k, v := range r {
			n[k] = v
		}
		delete(n, "ts")
		delete(n, "ts_ms")
		delete(n, "duration_us")
		delete(n, "machine_seq")
		if geoByVhost != nil {
			cc, ok := geoByVhost[eqU64(t, n, "vhost_id")]
			require.True(t, ok, "request_event for unexpected vhost: %v", r)
			n["bytes_in"] = n["bytes_in"].(float64) - float64(eqGeoBytesInDelta(cc))
			n["bytes_out"] = n["bytes_out"].(float64) - float64(len(cc))
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return eqU64(t, out[i], "vhost_id") < eqU64(t, out[j], "vhost_id") })
	return out
}

// eqUniques returns vhost → sorted client_hashes.
func eqUniques(t *testing.T, rows []map[string]any) map[uint64][]float64 {
	t.Helper()
	out := map[uint64][]float64{}
	for _, r := range eqRowsOfType(rows, "uniques") {
		vhost := eqU64(t, r, "vhost_id")
		raw, ok := r["client_hashes"].([]any)
		require.True(t, ok, "uniques row without client_hashes: %v", r)
		hashes := out[vhost]
		for _, h := range raw {
			hashes = append(hashes, h.(float64))
		}
		sort.Float64s(hashes)
		out[vhost] = hashes
	}
	return out
}

func eqAssertNoStrayRows(t *testing.T, shape string, rows []map[string]any) {
	t.Helper()
	for _, r := range rows {
		typ := r["_type"].(string)
		require.Contains(t, []string{"counter", "uniques", "request_event"}, typ,
			"%s: unexpected row type %q: %v", shape, typ, r)
		require.NotEqual(t, float64(0), r["vhost_id"],
			"%s: vhost-less row leaked (catch-all/monitor must not record): %v", shape, r)
		if typ == "request_event" {
			require.NotEqual(t, "unknown.test", r["host"], "%s: catch-all request recorded: %v", shape, r)
		}
	}
}

func TestGateShapeEquivalence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping caddytest integration test in -short mode (binds localhost ports)")
	}
	// The trace app's Provision requires its sink secret env var; the
	// sink stays dormant (no X-APX-Debug-Trace header is ever sent).
	t.Setenv("APX_INTERNAL_KEY", "gate-equivalence-trace-secret")

	mmdbPath, err := filepath.Abs("apx/testdata/GeoLite2-City-Test.mmdb")
	require.NoError(t, err)

	capA, getA := captureServer(t, http.StatusOK)
	capB, getB := captureServer(t, http.StatusOK)
	traceSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(capA.Close)
	t.Cleanup(capB.Close)
	t.Cleanup(traceSink.Close)

	// One in-process Caddy serves the whole test binary; keep BOTH shapes
	// on one admin port and load configs sequentially (a second port would
	// try to spawn a second in-process Caddy against shared globals).
	prevAdmin := caddytest.Default.AdminPort
	caddytest.Default.AdminPort = eqAdminPort
	t.Cleanup(func() { caddytest.Default.AdminPort = prevAdmin })

	// Unload the apps before the capture servers close (t.Cleanup is LIFO
	// and this is registered after the Close cleanups) so the flush loop
	// stops posting to dead sockets.
	t.Cleanup(func() {
		minimal := `{"admin":{"listen":"localhost:` + strconv.Itoa(eqAdminPort) + `"}}`
		req, err := http.NewRequest(http.MethodPost,
			fmt.Sprintf("http://localhost:%d/load", eqAdminPort), strings.NewReader(minimal))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if res, err := http.DefaultClient.Do(req); err == nil {
			res.Body.Close()
		}
	})

	var (
		respA, respB []eqResponse
		rowsA, rowsB []map[string]any
	)

	t.Run("shape_a_today", func(t *testing.T) {
		tester := caddytest.NewTester(t)
		tester.InitServer(eqConfig(false, capA.URL, traceSink.URL, mmdbPath), "json")
		respA = eqDrive(t)
		rowsA = eqWaitRows(t, getA)
	})
	t.Run("shape_b_gate", func(t *testing.T) {
		tester := caddytest.NewTester(t)
		tester.InitServer(eqConfig(true, capB.URL, traceSink.URL, mmdbPath), "json")
		respB = eqDrive(t)
		rowsB = eqWaitRows(t, getB)
	})
	if t.Failed() {
		t.Fatal("shape run failed; skipping comparisons")
	}

	// ---- Responses --------------------------------------------------

	// Strict A/B equality for the non-geo requests: status, body
	// (including the Geoip-Country echo, "" in both shapes), and headers.
	for i, name := range []string{"plain vhost", "xff vhost", "catch-all", "monitor probe"} {
		require.Equal(t, respA[i], respB[i], "response %d (%s) diverged", i, name)
	}
	require.Equal(t, 200, respA[0].status)
	require.Equal(t, eqHostA+" geo=[]", respA[0].body)
	require.Equal(t, 404, respA[2].status)
	require.Equal(t, "no-vhost geo=[]", respA[2].body)

	// Geo-divergent request (the documented scoping seam): Shape B must
	// resolve the real country end-to-end; Shape A has no geo at all.
	require.Equal(t, 200, respA[4].status)
	require.Equal(t, 200, respB[4].status)
	require.Equal(t, eqHostGeo+" geo=[]", respA[4].body, "shape A must have no geo")
	require.Equal(t, eqHostGeo+" geo=[GB]", respB[4].body,
		"shape B: gate provider + Geoip-Country route must resolve GB for %s", eqXffGeo)
	hA, hB := respA[4].headers.Clone(), respB[4].headers.Clone()
	hA.Del("Content-Length") // body differs by len("GB") by design
	hB.Del("Content-Length")
	require.Equal(t, hA, hB, "geo request: headers other than Content-Length must match")

	// ---- Captured NDJSON --------------------------------------------

	eqAssertNoStrayRows(t, "shape A", rowsA)
	eqAssertNoStrayRows(t, "shape B", rowsB)

	// Counters. Country is asserted per shape (scoping seam), then the
	// remaining identity + aggregates must match field-for-field after
	// reversing Shape B's exact Geoip-Country byte contribution.
	aggA, countriesA := eqCounters(t, rowsA)
	aggB, countriesB := eqCounters(t, rowsB)
	require.Equal(t, map[uint64]string{eqVhostA: "", eqVhostB: "", eqVhostGeo: ""}, countriesA,
		"shape A counters must have no country (no geo in shape A)")
	require.Equal(t, eqExpectedGeoB, countriesB,
		"shape B counters must carry the gate-resolved country")
	for id, a := range aggB {
		cc := eqExpectedGeoB[id.vhost]
		a.bytesIn -= a.count * eqGeoBytesInDelta(cc)
		a.bytesOut -= a.count * uint64(len(cc))
		aggB[id] = a
	}
	require.Equal(t, aggA, aggB, "counter rows diverged (post-normalization)")

	// Anchor absolute expectations so "both shapes broken the same way"
	// can't slip through: one row per vhost, monitor probe not counted,
	// static_response classifies as origin "cluster".
	require.Len(t, aggA, 3)
	for _, vhost := range []uint64{eqVhostA, eqVhostB, eqVhostGeo} {
		id := eqCounterID{vhost: vhost, method: "GET", status: 200, origin: "cluster", asn: 0}
		a, ok := aggA[id]
		require.True(t, ok, "missing counter row for vhost %d: %v", vhost, aggA)
		require.Equal(t, uint64(1), a.count, "vhost %d must count exactly one request", vhost)
	}

	// request_event rows: field-for-field after volatile-field removal
	// and Shape B byte normalization.
	evA := eqNormalizeRequestEvents(t, rowsA, nil)
	evB := eqNormalizeRequestEvents(t, rowsB, eqExpectedGeoB)
	require.Equal(t, evA, evB, "request_event rows diverged (post-normalization)")

	// Anchors on the XFF request's row (shared across shapes via evA==evB).
	require.Len(t, evA, 3)
	xffRow := evA[1] // sorted by vhost_id → 102
	require.Equal(t, float64(eqVhostB), xffRow["vhost_id"])
	require.Equal(t, "127.0.0.1", xffRow["client_ip"], "client_ip is RemoteAddr, never XFF")
	require.Equal(t, "203.0.113.9", xffRow["forwarded_ip"], "forwarded_ip is the RIGHTMOST XFF entry")
	require.Equal(t, "forwarded", xffRow["front_proxy"])
	require.Equal(t, "served", xffRow["disposition"])
	require.Equal(t, "cluster", xffRow["origin"])
	require.Equal(t, eqMachineID, xffRow["machine_id"])
	require.Equal(t, float64(1), xffRow["sample_rate"])
	require.Equal(t, eqUserAgent, xffRow["ua"])

	// Uniques: one hash per vhost in both shapes; XFF-hashed vhosts must
	// produce IDENTICAL hash values (rightmost-XFF + UA + salt are all
	// deterministic); the plain request hashes RemoteAddr including the
	// ephemeral port, so only its count is comparable.
	uniqA := eqUniques(t, rowsA)
	uniqB := eqUniques(t, rowsB)
	require.Len(t, uniqA, 3)
	require.Len(t, uniqB, 3)
	for vhost := range uniqA {
		require.Len(t, uniqA[vhost], 1, "shape A vhost %d uniques", vhost)
		require.Len(t, uniqB[vhost], 1, "shape B vhost %d uniques", vhost)
	}
	require.Equal(t, uniqA[eqVhostB], uniqB[eqVhostB], "XFF uniques hash must be deterministic across shapes")
	require.Equal(t, uniqA[eqVhostGeo], uniqB[eqVhostGeo], "XFF uniques hash must be deterministic across shapes")
}
