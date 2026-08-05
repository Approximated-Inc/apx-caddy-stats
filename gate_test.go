package apxstats

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// uniqueSnapshot complements the snapshot helpers in handler_test.go.
func (f *fakeApp) uniqueSnapshot() []recordedUnique {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedUnique, len(f.uniques))
	copy(out, f.uniques)
	return out
}

// --- A/B: the gate must record byte-identically to StatsHandler ---

// The only fields allowed to differ between two drives of the same request
// are wall-clock-derived: timestamps, measured duration (and its latency
// bucket), and the per-machine sequence. Everything else must be equal.
func normKeyRows(rows []recorded) []recorded {
	out := make([]recorded, len(rows))
	copy(out, rows)
	for i := range out {
		out[i].k.TsUnixMin = 0
		out[i].d.DurationUs = 0
		out[i].d.LatBucket = 0
	}
	return out
}

func normEventRows(rows []requestEventRow) []requestEventRow {
	out := make([]requestEventRow, len(rows))
	copy(out, rows)
	for i := range out {
		out[i].TsUnixSec = 0
		out[i].TsUnixMs = 0
		out[i].DurationUs = 0
		out[i].MachineSeq = 0
	}
	return out
}

func normUniqueRows(rows []recordedUnique) []recordedUnique {
	out := make([]recordedUnique, len(rows))
	copy(out, rows)
	for i := range out {
		out[i].tsUnixMin = 0
	}
	return out
}

func TestGate_ABRecordsIdenticallyToStatsHandler(t *testing.T) {
	// Drive the SAME request through StatsHandler and through GateHandler
	// (each with its own fakeApp) and diff every recorded artifact: counter
	// rows, request_events, challenge_attempts, unique-client hashes, and
	// the returned error. The gate must be indistinguishable.
	scenarios := []struct {
		name    string
		modeV2  bool
		newReq  func() *http.Request
		next    caddyhttp.Handler
		wantErr bool
	}{
		{
			name:   "served upstream 200",
			modeV2: true,
			newReq: func() *http.Request {
				r := newRequestWithReplacer("GET", "/api/users?token=secret", "100", upstreamSelected("10.0.0.1:8080"))
				r.RemoteAddr = "203.0.113.7:54321"
				r.Header.Set("User-Agent", "curl/8.0")
				r.Header.Set("X-Forwarded-For", "198.51.100.4, 203.0.113.7")
				return r
			},
			next: nextHandler(200),
		},
		{
			name:   "served upstream 200 legacy mode",
			modeV2: false,
			newReq: func() *http.Request {
				r := newRequestWithReplacer("GET", "/legacy", "100", upstreamSelected("10.0.0.1:8080"))
				r.RemoteAddr = "203.0.113.7:54321"
				r.Header.Set("User-Agent", "curl/8.0")
				return r
			},
			next: nextHandler(200),
		},
		{
			name:   "country from replacer static entry",
			modeV2: true,
			newReq: func() *http.Request {
				return newRequestWithReplacer("GET", "/geo", "100", map[string]any{
					"http.reverse_proxy.upstream.address": "10.0.0.1:8080",
					"geoip2.country_code":                 "gb",
				})
			},
			next: nextHandler(200),
		},
		{
			// The error value is constructed ONCE (caddyhttp.Error stamps a
			// random ID) so the A/B passthrough check can compare equality.
			name:   "rate limited 429 HandlerError",
			modeV2: true,
			newReq: func() *http.Request {
				return newRequestWithReplacer("GET", "/", "100", nil)
			},
			next: func() caddyhttp.Handler {
				rlErr := caddyhttp.Error(http.StatusTooManyRequests, nil)
				return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return rlErr
				})
			}(),
			wantErr: true,
		},
		{
			name:   "coraza interruption 403",
			modeV2: true,
			newReq: func() *http.Request {
				return newRequestWithReplacer("GET", "/?id=1'+OR+'1'='1", "100", nil)
			},
			next: func() caddyhttp.Handler {
				wafErr := caddyhttp.Error(http.StatusForbidden, errors.New("interruption triggered"))
				return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return wafErr
				})
			}(),
			wantErr: true,
		},
		{
			name:   "explicit block reason var",
			modeV2: true,
			newReq: func() *http.Request {
				return newRequestWithReplacer("GET", "/wp-login.php", "100", map[string]any{
					"http.vars.apx_block_reason": "waf",
				})
			},
			next: nextHandler(403),
		},
		{
			name:   "terminal challenge without vhost",
			modeV2: true,
			newReq: func() *http.Request {
				r := newRequestWithChallengeOutcome("GET", "/", "Example.COM:8443", "issued")
				r.RemoteAddr = "203.0.113.7:54321"
				return r
			},
			next: nextHandler(403),
		},
		{
			name:   "no vhost no challenge dropped",
			modeV2: true,
			newReq: func() *http.Request {
				return newRequestWithReplacer("GET", "/", "", nil)
			},
			next: nextHandler(404),
		},
		{
			name:   "edge verify outcome var set",
			modeV2: true,
			newReq: func() *http.Request {
				return newRequestWithVerifyOutcome("POST", "/checkout/123", "Example.COM:8443", "invalid")
			},
			next: nextHandler(403),
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			appA := &fakeApp{modeV2: sc.modeV2, machineID: "mach-1", hashSalt: "pepper"}
			appB := &fakeApp{modeV2: sc.modeV2, machineID: "mach-1", hashSalt: "pepper"}
			handler := &StatsHandler{app: appA}
			gate := &GateHandler{app: appB} // Geo "" → provider mode "off"

			errA := handler.ServeHTTP(httptest.NewRecorder(), sc.newReq(), sc.next)
			errB := gate.ServeHTTP(httptest.NewRecorder(), sc.newReq(), sc.next)

			if sc.wantErr {
				require.Error(t, errA)
				require.Error(t, errB)
			} else {
				require.NoError(t, errA)
				require.NoError(t, errB)
			}
			require.Equal(t, errA, errB, "servErr must match StatsHandler")

			require.Equal(t, normKeyRows(appA.snapshot()), normKeyRows(appB.snapshot()), "counter rows differ")
			require.Equal(t, normEventRows(appA.reqEventSnapshot()), normEventRows(appB.reqEventSnapshot()), "request_events differ")
			require.Equal(t, appA.challengeSnapshot(), appB.challengeSnapshot(), "challenge_attempts differ")
			require.Equal(t, appA.edgeVerifySnapshot(), appB.edgeVerifySnapshot(), "edge_verify_attempts differ")
			require.Equal(t, normUniqueRows(appA.uniqueSnapshot()), normUniqueRows(appB.uniqueSnapshot()), "unique-client rows differ")
		})
	}
}

// --- direct behavioral tests (same shapes the StatsHandler tests assert) ---

func TestGateServeHTTP_RecordsServedRequest(t *testing.T) {
	app := &fakeApp{modeV2: true, machineID: "mach-1"}
	g := &GateHandler{app: app}

	r := newRequestWithReplacer("GET", "/api/users?token=secret", "100", upstreamSelected("10.0.0.1:8080"))
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("User-Agent", "curl/8.0")
	w := httptest.NewRecorder()
	require.NoError(t, g.ServeHTTP(w, r, nextHandler(200)))

	recs := app.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, uint32(100), recs[0].k.VhostID)
	require.Equal(t, OriginUpstream, recs[0].k.Origin)
	require.Equal(t, uint16(200), recs[0].k.Status)

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, dispServed, evs[0].Disposition)
	require.Equal(t, "203.0.113.7", evs[0].ClientIP)
	require.Equal(t, "/api/users", evs[0].Path)
	require.True(t, evs[0].V2)
}

func TestGateServeHTTP_RateLimited429Disposition(t *testing.T) {
	app := &fakeApp{modeV2: true}
	g := &GateHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	err := g.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusTooManyRequests, nil)
	}))
	require.Error(t, err)

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, dispRateLimited, evs[0].Disposition)
	require.Equal(t, uint16(429), evs[0].Status)
	require.Equal(t, OriginClusterBlocked, app.snapshot()[0].k.Origin)
}

func TestGateServeHTTP_WafBlockedDisposition(t *testing.T) {
	app := &fakeApp{modeV2: true}
	g := &GateHandler{app: app}

	r := newRequestWithReplacer("GET", "/?id=1'+OR+'1'='1", "100", nil)
	w := httptest.NewRecorder()
	err := g.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusForbidden, errors.New("interruption triggered"))
	}))
	require.Error(t, err)

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, dispWafBlocked, evs[0].Disposition)
	require.Equal(t, OriginClusterBlocked, app.snapshot()[0].k.Origin)
	require.Equal(t, uint16(403), app.snapshot()[0].k.Status)
}

func TestGateServeHTTP_TerminalChallengeRecordsWithoutVhost(t *testing.T) {
	app := &fakeApp{modeV2: true}
	g := &GateHandler{app: app}

	r := newRequestWithChallengeOutcome("GET", "/", "Example.COM:8443", "issued")
	r.RemoteAddr = "203.0.113.7:54321"
	w := httptest.NewRecorder()
	require.NoError(t, g.ServeHTTP(w, r, nextHandler(403)))

	ch := app.challengeSnapshot()
	require.Len(t, ch, 1)
	require.Equal(t, "example.com", ch[0].vhost)
	require.Equal(t, "203.0.113.7", ch[0].ip)
	require.Equal(t, "issued", ch[0].outcome)

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, uint32(0), evs[0].VhostID)
	require.Equal(t, "example.com", evs[0].Host)
	require.Equal(t, dispChallengeIssued, evs[0].Disposition)
	require.Empty(t, app.snapshot(), "no counter row without vhost_id")
}

// hijackableRecorder lets the wrapped recorder's Hijack delegate succeed.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func TestGateServeHTTP_HijackedConnectionRecordsZeroBytesOut(t *testing.T) {
	app := &fakeApp{modeV2: true}
	g := &GateHandler{app: app}

	r := newRequestWithReplacer("GET", "/ws", "100", upstreamSelected("10.0.0.1:8080"))
	w := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	err := g.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		_, _, herr := w.(http.Hijacker).Hijack()
		return herr
	}))
	require.NoError(t, err)
	require.True(t, w.hijacked, "hijack must delegate to the inner writer")

	recs := app.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, uint64(0), recs[0].d.BytesOut, "post-hijack bytes are invisible; must record 0")
	require.Equal(t, uint16(200), recs[0].k.Status)
}

func TestGateServeHTTP_MonitorSkipRecordsNothingButGeoStillResolves(t *testing.T) {
	// Monitor probes must not be recorded, but the geo provider must still
	// be registered — today's geoip2 route runs for monitor traffic too, so
	// inner handlers keep resolving {geoip2.*} placeholders.
	app := &fakeApp{modeV2: true}
	g := &GateHandler{app: app, apx: geoProviderApp(t), Geo: "wild"}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	r.Header.Set("apx-monitor", "true")
	r.Header.Set("X-Forwarded-For", "81.2.69.142")
	r.RemoteAddr = "127.0.0.1:9999"

	before := testutil.ToFloat64(metricRequestsTotal.WithLabelValues("skipped_monitor"))

	var gotCC string
	var gotOK bool
	w := httptest.NewRecorder()
	err := g.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		gotCC, gotOK = repl.GetString("geoip2.country_code")
		w.WriteHeader(200)
		return nil
	}))
	require.NoError(t, err)

	require.True(t, gotOK, "geoip2.country_code must resolve on monitor requests")
	require.Equal(t, "GB", gotCC, "wild mode reads leftmost XFF against the test DB")
	require.Empty(t, app.snapshot(), "monitor requests record no counter row")
	require.Empty(t, app.reqEventSnapshot(), "monitor requests record no request_event")
	require.Empty(t, app.challengeSnapshot())
	require.Empty(t, app.uniqueSnapshot())

	after := testutil.ToFloat64(metricRequestsTotal.WithLabelValues("skipped_monitor"))
	require.Equal(t, 1.0, after-before, "skip metric mirrors StatsHandler")
}

func TestGateServeHTTP_EmptyGeoConfigMeansOff(t *testing.T) {
	// Geo "" must map to the explicit "off" mode — NOT fall through to the
	// provider's "" (= the fork's trusted_proxies default, which would run
	// a lookup from RemoteAddr). Off state: fixed keys resolve ("" , true).
	app := &fakeApp{modeV2: true}
	g := &GateHandler{app: app, apx: geoProviderApp(t), Geo: ""}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	r.RemoteAddr = "81.2.69.142:443" // would resolve GB if a lookup ran

	var gotCC string
	var gotOK bool
	w := httptest.NewRecorder()
	require.NoError(t, g.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		gotCC, gotOK = repl.GetString("geoip2.country_code")
		w.WriteHeader(200)
		return nil
	})))

	require.True(t, gotOK, "fixed keys stay resolvable when geo is off")
	require.Equal(t, "", gotCC, "no lookup may run when Geo config is empty")
}

func TestGateServeHTTP_WildGeoResolvesForInnerHandlers(t *testing.T) {
	app := &fakeApp{modeV2: true}
	g := &GateHandler{app: app, apx: geoProviderApp(t), Geo: "wild"}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	r.Header.Set("X-Forwarded-For", "89.160.20.128")
	r.RemoteAddr = "127.0.0.1:9999"

	var gotCC string
	w := httptest.NewRecorder()
	require.NoError(t, g.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		gotCC, _ = repl.GetString("geoip2.country_code")
		w.WriteHeader(200)
		return nil
	})))
	require.Equal(t, "SE", gotCC)

	// And the recorded counter row picked the country up too (readCountry
	// resolves through the same provider on the response path).
	recs := app.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, "SE", recs[0].k.Country)
}

func TestGateServeHTTP_ServErrPassthrough(t *testing.T) {
	app := &fakeApp{modeV2: true}
	g := &GateHandler{app: app}

	sentinel := caddyhttp.Error(http.StatusBadGateway, errors.New("dial: connection refused"))
	r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	err := g.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return sentinel
	}))
	require.Equal(t, sentinel, err, "servErr must be returned unchanged")
	require.Equal(t, OriginClusterProxyError, app.snapshot()[0].k.Origin)
}

func TestGateProvision_ErrorsWhenAppsMissing(t *testing.T) {
	// A context without any configured apps (bare NewContext) must hard-fail
	// Provision — silently instantiating empty apps would drop counters and
	// serve empty geo.
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	g := new(GateHandler)
	err := g.Provision(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, caddy.ErrNotConfigured)
	require.ErrorContains(t, err, "apx_stats")

	// With the stats app already injected, the apx app is still required.
	g2 := &GateHandler{app: &fakeApp{}}
	err = g2.Provision(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, caddy.ErrNotConfigured)
	require.ErrorContains(t, err, "apx app")
}
