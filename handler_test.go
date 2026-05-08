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
	psID     uint32
}

type recorded struct {
	k Key
	d CounterDelta
}

func (f *fakeApp) Record(k Key, d CounterDelta) {
	f.mu.Lock()
	f.records = append(f.records, recorded{k, d})
	f.mu.Unlock()
}

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

func TestServeHTTP_RecordsBytesOut(t *testing.T) {
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
	require.Equal(t, uint64(12345), app.snapshot()[0].d.BytesOut)
}

func TestServeHTTP_RecordsBytesInFromContentLength(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("POST", "/", "100", nil)
	r.ContentLength = 4096
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))
	require.Equal(t, uint64(4096), app.snapshot()[0].d.BytesIn)
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

func TestServeHTTP_SkipsApxMonitorAnyValue(t *testing.T) {
	// Defensive: the URL monitor sets "true" today but we treat the
	// presence of the header as the signal — any non-empty value skips.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	for _, v := range []string{"true", "1", "yes", "monitor"} {
		r := newRequestWithReplacer("GET", "/", "100", nil)
		r.Header.Set("apx-monitor", v)
		w := httptest.NewRecorder()
		require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))
	}
	require.Empty(t, app.snapshot())
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
