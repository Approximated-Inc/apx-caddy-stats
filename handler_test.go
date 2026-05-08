package apxstats

import (
	"context"
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

// upstreamWithStatus simulates a reverse_proxy outcome by setting the
// two placeholders the classifier reads.
func upstreamWithStatus(addr string, status int) map[string]any {
	m := map[string]any{}
	if addr != "" {
		m["http.reverse_proxy.upstream.address"] = addr
	}
	if status > 0 {
		m["http.reverse_proxy.status_code"] = status
	}
	return m
}

func nextHandler(status int) caddyhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("ok"))
		return nil
	}
}

func TestServeHTTP_ClassifiesUpstreamWhenStatusMatches(t *testing.T) {
	app := &fakeApp{psID: 42}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/foo", "100", upstreamWithStatus("10.0.0.1:8080", 200))
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	recs := app.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, OriginUpstream, recs[0].k.Origin)
	require.Equal(t, uint32(100), recs[0].k.VhostID)
	require.Equal(t, "GET", recs[0].k.Method)
	require.Equal(t, uint16(200), recs[0].k.Status)
}

func TestServeHTTP_ClassifiesClusterWhenNoUpstream(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(404)))

	recs := app.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, OriginCluster, recs[0].k.Origin)
	require.Equal(t, uint16(404), recs[0].k.Status)
}

func TestServeHTTP_ClassifiesClusterProxyErrorWhenStatusDiffers(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	// Upstream returned 502 but Caddy synthesized a 503 (or vice versa).
	r := newRequestWithReplacer("GET", "/", "100", upstreamWithStatus("10.0.0.1:8080", 502))
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(503)))

	recs := app.snapshot()
	require.Equal(t, OriginClusterProxyError, recs[0].k.Origin)
}

func TestServeHTTP_ClassifiesClusterProxyErrorWhenUpstreamDialFailed(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	// Upstream address is set (proxy was attempted) but no status came
	// back — classic dial-failed / connection-refused outcome.
	r := newRequestWithReplacer("GET", "/", "100", map[string]any{
		"http.reverse_proxy.upstream.address": "10.0.0.1:8080",
	})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(502)))

	recs := app.snapshot()
	require.Equal(t, OriginClusterProxyError, recs[0].k.Origin)
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
