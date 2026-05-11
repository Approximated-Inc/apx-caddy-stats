package apxstats

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// fakeApp captures calls to Record so handler tests can assert.
type fakeApp struct {
	mu       sync.Mutex
	records  []recorded
	uniques  []recordedUnique
	psID     uint32
	hashSalt string
}

type recorded struct {
	k Key
	d CounterDelta
}

type recordedUnique struct {
	tsUnixMin uint32
	vhostID   uint32
	hash      uint64
}

func (f *fakeApp) Record(k Key, d CounterDelta) {
	f.mu.Lock()
	f.records = append(f.records, recorded{k, d})
	f.mu.Unlock()
}

func (f *fakeApp) RecordUnique(tsUnixMin, vhostID uint32, hash uint64) {
	f.mu.Lock()
	f.uniques = append(f.uniques, recordedUnique{tsUnixMin, vhostID, hash})
	f.mu.Unlock()
}

func (f *fakeApp) HashSalt() string { return f.hashSalt }

func (f *fakeApp) ProxyServerID() uint32 { return f.psID }

func (f *fakeApp) snapshot() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recorded, len(f.records))
	copy(out, f.records)
	return out
}

// newRequestWithReplacer creates a request whose context has a Caddy
// Replacer + a vhost_id var, so the handler can read both. Mirrors what
// caddyhttp.Server.ServeHTTP installs on the context in production.
func newRequestWithReplacer(method, target string, vhostID string, replEntries map[string]any) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	repl := caddy.NewReplacer()
	for k, v := range replEntries {
		repl.Set(k, v)
	}
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	vars := map[string]any{}
	if vhostID != "" {
		vars["vhost_id"] = vhostID
	}
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, vars)
	return r.WithContext(ctx)
}

// upstreamSelected simulates reverse_proxy selecting an upstream by
// setting the address placeholder. Caddy sets this BEFORE the dial,
// regardless of whether the dial then succeeds — so presence of the
// placeholder alone means "reverse_proxy ran." Whether it succeeded is
// determined by the error returned from next.ServeHTTP, not from
// status_code (which Caddy doesn't set for normal pass-through).
func upstreamSelected(addr string) map[string]any {
	if addr == "" {
		return nil
	}
	return map[string]any{"http.reverse_proxy.upstream.address": addr}
}

func nextHandler(status int) caddyhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("ok"))
		return nil
	}
}

func TestServeHTTP_ClassifiesUpstreamWhenProxySucceeds(t *testing.T) {
	app := &fakeApp{psID: 42}
	h := &StatsHandler{app: app}

	// reverse_proxy ran (upstream.address set), no error bubbled up — the
	// upstream responded and Caddy passed through. Caddy never sets
	// {http.reverse_proxy.status_code} for pass-through, so we can't and
	// don't try to compare upstream status to final status.
	r := newRequestWithReplacer("GET", "/foo", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	recs := app.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, OriginUpstream, recs[0].k.Origin)
	require.Equal(t, uint32(100), recs[0].k.VhostID)
	require.Equal(t, "GET", recs[0].k.Method)
	require.Equal(t, uint16(200), recs[0].k.Status)
}

func TestServeHTTP_ClassifiesUpstreamWhenUpstreamReturns4xx(t *testing.T) {
	// Customer's upstream returns 404 (or any 4xx/5xx). Caddy passes it
	// through with no error. Origin must still be upstream — that's a
	// real upstream response, not Caddy synthesizing.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(404)))

	require.Equal(t, OriginUpstream, app.snapshot()[0].k.Origin)
}

func TestServeHTTP_ClassifiesClusterWhenNoUpstream(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	// No upstream.address placeholder — reverse_proxy never ran. Could be
	// a 404 from no-route-match, a redirect, a static_response, etc.
	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(404)))

	recs := app.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, OriginCluster, recs[0].k.Origin)
	require.Equal(t, uint16(404), recs[0].k.Status)
}

func TestServeHTTP_ClassifiesClusterBlockedWhenBlockReasonSet(t *testing.T) {
	// Some upstream-of-apx_stats handler (WAF, rate limit) blocked the
	// request and set `http.vars.apx_block_reason` to mark it. We
	// classify those as cluster_blocked, not cluster, so dashboards
	// distinguish "Caddy deliberately blocked" from "Caddy handled it
	// itself (redirect / 404)."
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", map[string]any{
		"http.vars.apx_block_reason": "waf",
	})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(403)))

	recs := app.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, OriginClusterBlocked, recs[0].k.Origin)
	require.Equal(t, uint16(403), recs[0].k.Status)
}

func TestServeHTTP_BlockedClassificationBeatsClusterEvenWhenNoUpstream(t *testing.T) {
	// Belt-and-suspenders: when both signals indicate "no upstream", the
	// block-reason variant wins so we see it in the stats.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", map[string]any{
		"http.vars.apx_block_reason": "rate_limit",
	})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(429)))

	require.Equal(t, OriginClusterBlocked, app.snapshot()[0].k.Origin)
}

func TestServeHTTP_ClassifiesClusterProxyErrorWhenReverseProxyFails(t *testing.T) {
	// reverse_proxy failed its dial / timed out. It returned a
	// HandlerError that bubbled up through subroute → us.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	failingNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusBadGateway, errors.New("dial: connection refused"))
	})
	err := h.ServeHTTP(w, r, failingNext)
	require.Error(t, err)

	require.Equal(t, OriginClusterProxyError, app.snapshot()[0].k.Origin)
}

func TestServeHTTP_RecordsHandlerErrorStatusWhenResponseUnwritten(t *testing.T) {
	// reverse_proxy returned HandlerError{502} without writing the
	// response — Caddy will synthesize the 502 at the outer error
	// handler. Our recorded status must reflect what the client sees,
	// not the recorder's default of 200.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	failingNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusBadGateway, errors.New("dial: connection refused"))
	})
	_ = h.ServeHTTP(w, r, failingNext)

	rec := app.snapshot()[0]
	require.Equal(t, uint16(502), rec.k.Status, "must record the synthesized 502, not default 200")
}

func TestServeHTTP_ClassifiesClusterProxyErrorOnTimeoutGateway(t *testing.T) {
	// 504 Gateway Timeout — the other common reverse_proxy failure mode.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	timeoutNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusGatewayTimeout, errors.New("upstream timeout"))
	})
	_ = h.ServeHTTP(w, r, timeoutNext)

	require.Equal(t, OriginClusterProxyError, app.snapshot()[0].k.Origin)
}

func TestServeHTTP_ReadsCountryAndASN(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	repl := map[string]any{
		"geoip2.country_code":              "DE",
		"geoip2.autonomous_system_number":  "13335",
	}
	r := newRequestWithReplacer("GET", "/", "100", repl)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	recs := app.snapshot()
	require.Equal(t, "DE", recs[0].k.Country)
	require.Equal(t, uint32(13335), recs[0].k.ASN)
}

func TestServeHTTP_NormalizesCountryToUppercase(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", map[string]any{
		"geoip2.country_code": "us",
	})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))
	require.Equal(t, "US", app.snapshot()[0].k.Country)
}

func TestServeHTTP_DropsRowWhenVhostIDAbsent(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	// No vars context, no vhost_id — handler must not record.
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))
	require.Empty(t, app.snapshot())
}

func TestResponseBytes_ZeroOnHijackedConnection(t *testing.T) {
	// WebSocket upgrades and raw-TCP proxy: handler hijacks the
	// connection and writes the upgrade response post-hijack on a bare
	// net.Conn that we can't see. Counting bytes-out via w.Header() at
	// that point would fabricate ~100-200 bytes per upgrade — observed
	// inflation on WebSocket-heavy customers. Verify responseBytes
	// returns 0 when the recorder is hijacked.
	rec := &recorder{
		ResponseWriter: httptest.NewRecorder(),
		status:         200,
		wrote:          true,
		hijacked:       true,
	}
	require.Equal(t, uint64(0), responseBytes(rec))
}

func TestServeHTTP_BytesOutIncludesBodyAndHeaders(t *testing.T) {
	// "Bandwidth out" is request-line + headers + body, not just body.
	// Most response variability is in the body; headers add a small
	// constant per response.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		_, _ = w.Write(make([]byte, 12345))
		return nil
	})
	require.NoError(t, h.ServeHTTP(w, r, next))
	bytesOut := app.snapshot()[0].d.BytesOut
	require.Greater(t, bytesOut, uint64(12345), "must include status line + headers, not just body")
	// Loose upper bound — status line + a handful of headers shouldn't
	// add more than a few hundred bytes on top of the body.
	require.Less(t, bytesOut, uint64(12345+1024))
}

func TestServeHTTP_BytesInIncludesHeadersEvenForGet(t *testing.T) {
	// Bandwidth-in for a GET (no body) used to record 0. It should now
	// reflect the request line + headers — the only inbound bytes a GET
	// produces.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/some/path", "100", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (something)")
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	bytesIn := app.snapshot()[0].d.BytesIn
	require.Greater(t, bytesIn, uint64(0), "GET with no body must still record header bytes")
}

func TestServeHTTP_BytesInIncludesContentLengthForPost(t *testing.T) {
	// POST body via Content-Length is added on top of headers.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("POST", "/", "100", nil)
	r.ContentLength = 4096
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	bytesIn := app.snapshot()[0].d.BytesIn
	require.GreaterOrEqual(t, bytesIn, uint64(4096), "must include body bytes")
	// The headers contribute their own bytes too, so > 4096.
	require.Greater(t, bytesIn, uint64(4096))
}

func TestServeHTTP_BytesOutZeroWhenResponseUnwritten(t *testing.T) {
	// Reverse-proxy failure path: HandlerError bubbles up, Caddy
	// synthesizes the response AFTER our outer handler returns. Our
	// recorder never sees those bytes, so we record 0 for bytes_out.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	failingNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusBadGateway, errors.New("dial: connection refused"))
	})
	_ = h.ServeHTTP(w, r, failingNext)

	require.Equal(t, uint64(0), app.snapshot()[0].d.BytesOut)
}

func TestServeHTTP_BucketsLatency(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	rec := app.snapshot()[0]
	// Whatever bucket the no-op handler ends up in, it must be a valid
	// index AND match the recorded duration.
	require.GreaterOrEqual(t, rec.d.LatBucket, 0)
	require.Less(t, rec.d.LatBucket, HistogramBuckets)
	require.Equal(t, BucketForUs(rec.d.DurationUs), rec.d.LatBucket)
}

func TestServeHTTP_ClampsExoticMethodToOTHER(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("PROPFIND", "/", "100", nil)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))
	require.Equal(t, "OTHER", app.snapshot()[0].k.Method)
}

func TestServeHTTP_SkipsApxMonitorRequests(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	// URL monitor probe — carries apx-monitor: true. Must not record.
	r := newRequestWithReplacer("GET", "/", "100", nil)
	r.Header.Set("apx-monitor", "true")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))
	require.Empty(t, app.snapshot(), "monitor requests must not be recorded")

	// Normal request still records.
	r2 := newRequestWithReplacer("GET", "/", "100", nil)
	w2 := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w2, r2, nextHandler(200)))
	require.Len(t, app.snapshot(), 1, "non-monitor request should record")
}

func TestServeHTTP_SkipsOnlyExactlyTrueApxMonitor(t *testing.T) {
	// Match against the exact "true" sentinel — any other value MUST
	// record. Otherwise an external client can hide their traffic from
	// the customer's analytics by setting `apx-monitor: anything`.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	// "true" skips.
	r := newRequestWithReplacer("GET", "/", "100", nil)
	r.Header.Set("apx-monitor", "true")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))
	require.Empty(t, app.snapshot(), "apx-monitor: true must skip recording")

	// Other values DO record.
	for _, v := range []string{"1", "yes", "monitor", "TRUE", "true ", " true"} {
		r := newRequestWithReplacer("GET", "/", "100", nil)
		r.Header.Set("apx-monitor", v)
		w := httptest.NewRecorder()
		require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))
	}
	require.Len(t, app.snapshot(), 6, "non-exact apx-monitor values must record (no bypass)")
}

func TestServeHTTP_KeyIsMinuteAligned(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	rec := app.snapshot()[0]
	require.NotZero(t, rec.k.TsUnixMin)
	// Two requests in the same minute must collapse to the same key.
	r2 := newRequestWithReplacer("GET", "/", "100", nil)
	w2 := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w2, r2, nextHandler(200)))
	rec2 := app.snapshot()[1]
	require.Equal(t, rec.k.TsUnixMin, rec2.k.TsUnixMin)
}
