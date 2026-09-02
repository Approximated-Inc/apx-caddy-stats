package apxstats

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// fakeApp captures calls to Record so handler tests can assert.
type fakeApp struct {
	mu           sync.Mutex
	records      []recorded
	uniques      []recordedUnique
	reqEvents    []requestEventRow
	challenges   []challengeAttemptKey
	edgeVerifies []edgeVerifyAttemptKey
	psID         uint32
	hashSalt     string
	machineID    string
	modeV2       bool
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

func (f *fakeApp) RecordRequestEvent(row requestEventRow) {
	f.mu.Lock()
	f.reqEvents = append(f.reqEvents, row)
	f.mu.Unlock()
}

func (f *fakeApp) RecordChallengeAttempt(key challengeAttemptKey) {
	f.mu.Lock()
	f.challenges = append(f.challenges, key)
	f.mu.Unlock()
}

func (f *fakeApp) RecordEdgeVerifyAttempt(key edgeVerifyAttemptKey) {
	f.mu.Lock()
	f.edgeVerifies = append(f.edgeVerifies, key)
	f.mu.Unlock()
}

func (f *fakeApp) HashSalt() string { return f.hashSalt }

func (f *fakeApp) ProxyServerID() uint32 { return f.psID }

func (f *fakeApp) MachineID() string         { return f.machineID }
func (f *fakeApp) RequestEventsModeV2() bool { return f.modeV2 }

func (f *fakeApp) challengeSnapshot() []challengeAttemptKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]challengeAttemptKey, len(f.challenges))
	copy(out, f.challenges)
	return out
}

func (f *fakeApp) edgeVerifySnapshot() []edgeVerifyAttemptKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]edgeVerifyAttemptKey, len(f.edgeVerifies))
	copy(out, f.edgeVerifies)
	return out
}

func (f *fakeApp) reqEventSnapshot() []requestEventRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]requestEventRow, len(f.reqEvents))
	copy(out, f.reqEvents)
	return out
}

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
		"geoip2.country_code":             "DE",
		"geoip2.autonomous_system_number": "13335",
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

// newRequestWithChallengeOutcome builds a request whose context carries a
// caddyhttp vars map with `apx_challenge_outcome` set — mirroring what the
// apx_challenge handler does via caddyhttp.SetVar. No vhost_id is set: a
// served challenge is terminal, so the per-vhost vars handler never ran.
func newRequestWithChallengeOutcome(method, target, host, outcome string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
	r = r.WithContext(ctx)
	if outcome != "" {
		caddyhttp.SetVar(r.Context(), "apx_challenge_outcome", outcome)
	}
	return r
}

func TestServeHTTP_RecordsChallengeAttemptWhenOutcomeVarSet(t *testing.T) {
	// A request carrying apx_challenge_outcome records one challenge_attempt
	// keyed by lowercased Host (port stripped) + security client IP +
	// outcome — even though no vhost_id is set (served challenge is terminal).
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithChallengeOutcome("GET", "/some/path", "Example.COM:8443", "issued")
	r.RemoteAddr = "203.0.113.7:54321"
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(403)))

	ch := app.challengeSnapshot()
	require.Len(t, ch, 1)
	require.Equal(t, "example.com", ch[0].vhost, "Host lowercased + port stripped")
	require.Equal(t, "203.0.113.7", ch[0].ip, "security client IP, port stripped")
	require.Equal(t, "issued", ch[0].outcome)
}

func TestServeHTTP_RecordsChallengeAttemptWithoutVhostID(t *testing.T) {
	// Belt-and-suspenders: no vhost_id var at all (the served-challenge
	// reality). The challenge_attempt must still record; the counter row
	// is correctly skipped (no_vhost).
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithChallengeOutcome("GET", "/", "blocked.example.com", "failed")
	r.RemoteAddr = "198.51.100.9:1234"
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(403)))

	require.Len(t, app.challengeSnapshot(), 1, "challenge recorded despite missing vhost_id")
	require.Empty(t, app.snapshot(), "no counter row without vhost_id")
}

func TestServeHTTP_NoChallengeAttemptWhenVarUnset(t *testing.T) {
	// A normal request (no apx_challenge_outcome var) records no
	// challenge_attempt.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	require.Empty(t, app.challengeSnapshot(), "no challenge var → no challenge_attempt")
}

func TestServeHTTP_ChallengeVhostFallbackWhenNoPort(t *testing.T) {
	// Host without a :port (the common HTTP/2 / default-port case) must
	// still lowercase cleanly.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithChallengeOutcome("GET", "/", "API.Example.COM", "passed")
	r.RemoteAddr = "203.0.113.7:443"
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	ch := app.challengeSnapshot()
	require.Len(t, ch, 1)
	require.Equal(t, "api.example.com", ch[0].vhost)
}

// newRequestWithVerifyOutcome builds a request whose context carries a
// caddyhttp vars map with `apx_verify_outcome` set — mirroring what the
// Edge Verify edge handler does via caddyhttp.SetVar.
func newRequestWithVerifyOutcome(method, target, host, outcome string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
	r = r.WithContext(ctx)
	if outcome != "" {
		caddyhttp.SetVar(r.Context(), "apx_verify_outcome", outcome)
	}
	return r
}

func TestServeHTTP_RecordsEdgeVerifyAttemptWhenOutcomeVarSet(t *testing.T) {
	// A request carrying apx_verify_outcome records one edge_verify_attempt
	// keyed by lowercased Host (port stripped) + bucketed path + outcome.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithVerifyOutcome("POST", "/checkout/123", "Example.COM:8443", "invalid")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(403)))

	attempts := app.edgeVerifySnapshot()
	require.Len(t, attempts, 1)
	require.Equal(t, "example.com", attempts[0].vhost, "Host lowercased + port stripped")
	require.Equal(t, "/checkout/*", attempts[0].pathBucket, "path bucketed (numeric id starred)")
	require.Equal(t, "invalid", attempts[0].outcome)
}

func TestServeHTTP_NoEdgeVerifyAttemptWhenVarUnset(t *testing.T) {
	// A normal request (no apx_verify_outcome var) records no
	// edge_verify_attempt.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	require.Empty(t, app.edgeVerifySnapshot(), "no verify var → no edge_verify_attempt")
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

func TestMethodOrUnknown_returnsStaticVerbNotRequestLineSlice(t *testing.T) {
	// On HTTP/1.1, r.Method is a slice of the FULL request line (method +
	// URI + proto share one backing array, experimentally confirmed). The
	// returned method is buffered in both the counter map Key and the
	// request_events rows, so returning m itself would pin the whole
	// (attacker-length-controlled, up to ~1MB) line per buffered entry
	// while the byte accounting counts only len("POST"). The function must
	// return the static net/http package constant instead.
	backing := "POST" + strings.Repeat("a", 1<<20) // runtime-built, never rodata
	m := backing[:4]
	got := methodOrUnknown(m)
	require.Equal(t, "POST", got)
	if unsafe.StringData(got) == unsafe.StringData(backing) {
		t.Error("methodOrUnknown returned the request-line slice; want the static verb constant")
	}
	// Non-standard methods already clamp to the static "OTHER" sentinel.
	junk := backing[:5] // "POSTa" — not a standard verb
	require.Equal(t, "OTHER", methodOrUnknown(junk))
}

func TestServeHTTP_bufferedMethodAndPathDoNotPinRequestLine(t *testing.T) {
	// End-to-end through the real handler: the Method buffered in the
	// counter Key and the Method/Path buffered in the request_event row
	// must not share the request-line backing array.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("POST", "/api/users", "100", upstreamSelected("10.0.0.1:8080"))
	methodBacking := "POST" + strings.Repeat("a", 1<<20)
	r.Method = methodBacking[:4]
	// A short query-less path can still be a slice of a huge request line
	// (absolute-form URI host, junk long method) — model that directly.
	pathBacking := "/api/users" + strings.Repeat("b", 1<<20)
	r.URL.Path = pathBacking[:10]

	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	rec := app.snapshot()[0]
	require.Equal(t, "POST", rec.k.Method)
	if unsafe.StringData(rec.k.Method) == unsafe.StringData(methodBacking) {
		t.Error("buffered Key.Method shares the request-line backing; want the static verb constant")
	}

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, "POST", evs[0].Method)
	if unsafe.StringData(evs[0].Method) == unsafe.StringData(methodBacking) {
		t.Error("buffered request_event Method shares the request-line backing; want the static verb constant")
	}
	require.Equal(t, "/api/users", evs[0].Path)
	if unsafe.StringData(evs[0].Path) == unsafe.StringData(pathBacking) {
		t.Error("buffered request_event Path shares the request-line backing; want an owned copy")
	}
}

func TestChallengeVhost_boundsHostWidth(t *testing.T) {
	// The challenge map keys by the Host header — attacker-supplied and,
	// unlike real hostnames (DNS caps at 253), unbounded on the wire. Cap
	// the buffered key width like the coraza host field (255).
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = strings.Repeat("h", 300)
	require.Len(t, challengeVhost(r), 255)
	// Normal hosts pass through lowercased + port-stripped, as before.
	r.Host = "EXAMPLE.com:8443"
	require.Equal(t, "example.com", challengeVhost(r))
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

func TestServeHTTP_RecordsRequestEventForServedRequest(t *testing.T) {
	// A served request (no apx_block_reason) records one request_event row
	// with the security client IP from RemoteAddr, capped path, final status,
	// and the served origin.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/api/users?token=secret", "100", upstreamSelected("10.0.0.1:8080"))
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("User-Agent", "curl/8.0")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	ev := evs[0]
	require.Equal(t, uint32(100), ev.VhostID)
	require.Equal(t, "203.0.113.7", ev.ClientIP) // securityClientIP, port stripped
	require.Equal(t, "GET", ev.Method)
	require.Equal(t, "/api/users", ev.Path) // capPath strips the query
	require.Equal(t, "/api/users", ev.PathBucket)
	require.Equal(t, uint16(200), ev.Status)
	require.Equal(t, "curl/8.0", ev.UA)
	require.Equal(t, OriginUpstream, ev.Origin)
	require.NotZero(t, ev.TsUnixSec)
}

func TestServeHTTP_SkipsRequestEventWhenBlockReasonSet(t *testing.T) {
	// WAF-blocked / rate-limited requests carry apx_block_reason — they must
	// NOT record a request_event (they live in request_counters +
	// coraza_detection_events). The counter row is still recorded.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/wp-login.php", "100", map[string]any{
		"http.vars.apx_block_reason": "waf",
	})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(403)))

	require.Empty(t, app.reqEventSnapshot(), "blocked requests record no request_event")
	require.Len(t, app.snapshot(), 1, "counter row still recorded for blocked request")
}

func TestServeHTTP_InfersWafBlockFromCorazaInterruption(t *testing.T) {
	// coraza-caddy (block mode) terminates the chain and returns a
	// HandlerError whose message is "interruption triggered" (no var set).
	// We infer reason="waf": no request_event, counter classified blocked.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/?id=1'+OR+'1'='1", "100", nil)
	w := httptest.NewRecorder()
	corazaBlock := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusForbidden, errors.New("interruption triggered"))
	})
	err := h.ServeHTTP(w, r, corazaBlock)
	require.Error(t, err)

	require.Empty(t, app.reqEventSnapshot(), "coraza-blocked request records no request_event")
	require.Len(t, app.snapshot(), 1)
	require.Equal(t, OriginClusterBlocked, app.snapshot()[0].k.Origin)
	require.Equal(t, uint16(403), app.snapshot()[0].k.Status)
}

func TestServeHTTP_InfersRateLimitBlockFrom429HandlerError(t *testing.T) {
	// The apx rate_limit fork rejects with caddyhttp.Error(429, nil), which
	// bubbles up as a HandlerError{429} (no var set). We infer
	// reason="rate_limit": no request_event, counter classified blocked.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	rateLimited := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusTooManyRequests, nil)
	})
	err := h.ServeHTTP(w, r, rateLimited)
	require.Error(t, err)

	require.Empty(t, app.reqEventSnapshot(), "rate-limited request records no request_event")
	require.Len(t, app.snapshot(), 1)
	require.Equal(t, OriginClusterBlocked, app.snapshot()[0].k.Origin)
	require.Equal(t, uint16(429), app.snapshot()[0].k.Status)
}

func TestServeHTTP_ProxyErrorIsNotInferredAsBlock(t *testing.T) {
	// A reverse_proxy failure returns a HandlerError too (502, with an
	// upstream selected) — it must NOT be read as a block. The request is
	// recorded as a served event with cluster_proxy_error origin.
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	proxyFail := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusBadGateway, errors.New("dial: connection refused"))
	})
	err := h.ServeHTTP(w, r, proxyFail)
	require.Error(t, err)

	require.Len(t, app.reqEventSnapshot(), 1, "proxy error is served, not blocked — records a request_event")
	require.Equal(t, OriginClusterProxyError, app.snapshot()[0].k.Origin)
}

func TestServeHTTP_RequestEventTruncatesLongPathAndUA(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}

	longPath := "/" + strings.Repeat("a", 2000)
	longUA := strings.Repeat("u", 1000)
	r := newRequestWithReplacer("GET", longPath, "100", upstreamSelected("10.0.0.1:8080"))
	r.Header.Set("User-Agent", longUA)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.LessOrEqual(t, len(evs[0].Path), 1024)
	require.LessOrEqual(t, len(evs[0].UA), 512)
	require.True(t, utf8.ValidString(evs[0].Path))
	require.True(t, utf8.ValidString(evs[0].UA))
}

func TestServeHTTP_V2RecordsBlockedRequestEventWithDisposition(t *testing.T) {
	// mode_v2: a WAF-blocked request (apx_block_reason=waf) is now LOGGED as
	// a request_event with disposition=waf_blocked (legacy mode skipped it).
	app := &fakeApp{modeV2: true, machineID: "mach-1"}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/wp-login.php", "100", map[string]any{
		"http.vars.apx_block_reason": "waf",
	})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(403)))

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1, "v2 logs blocked requests")
	require.Equal(t, dispWafBlocked, evs[0].Disposition)
	require.Equal(t, uint32(100), evs[0].VhostID)
	require.Equal(t, "", evs[0].Host, "host empty when vhost_id>0")
	require.True(t, evs[0].V2)
	require.Equal(t, "mach-1", evs[0].MachineID)
	require.NotZero(t, evs[0].TsUnixMs)
	require.NotZero(t, evs[0].MachineSeq)
}

func TestServeHTTP_V2RowCarriesResolvedMachineID(t *testing.T) {
	// End-to-end over the REAL app: config placeholder → Provision →
	// the row the recorder buffers. Regression guard for the fleet-wide bug
	// where every row shipped the literal "{env.FLY_MACHINE_ID}".
	t.Setenv("FLY_MACHINE_ID", "148e394f7e9218")
	a, err := provisionApp(t, &IngestConfig{
		URL:           "http://unused",
		AuthToken:     "cfg-token",
		RequestEvents: &RequestEventsConfig{Enabled: true, ModeV2: true, MaxRows: 100},
	}, withMachineID("{env.FLY_MACHINE_ID}"))
	require.NoError(t, err)

	h := &StatsHandler{app: a}
	r := newRequestWithReplacer("GET", "/", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	rows, _ := a.requestEvents.drain()
	require.Len(t, rows, 1)
	require.True(t, rows[0].V2)
	require.Equal(t, "148e394f7e9218", rows[0].MachineID)
}

func TestServeHTTP_V2RecordsRateLimitedDisposition(t *testing.T) {
	app := &fakeApp{modeV2: true}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/", "100", nil)
	w := httptest.NewRecorder()
	rateLimited := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusTooManyRequests, nil)
	})
	_ = h.ServeHTTP(w, r, rateLimited)

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, dispRateLimited, evs[0].Disposition)
	require.Equal(t, uint16(429), evs[0].Status)
}

func TestServeHTTP_V2RecordsTerminalChallengeWithHostAndZeroVhost(t *testing.T) {
	// mode_v2: a terminal challenge has NO vhost_id (apx_challenge returns
	// before the per-vhost vars handler). It must still be logged with
	// vhost_id=0, host set (lowercased/port-stripped), disposition mapped.
	app := &fakeApp{modeV2: true}
	h := &StatsHandler{app: app}

	r := newRequestWithChallengeOutcome("GET", "/", "Example.COM:8443", "issued")
	r.RemoteAddr = "203.0.113.7:54321"
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(403)))

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1, "terminal challenge logged despite missing vhost_id")
	require.Equal(t, uint32(0), evs[0].VhostID)
	require.Equal(t, "example.com", evs[0].Host)
	require.Equal(t, dispChallengeIssued, evs[0].Disposition)
	// The challenge_attempt counter is still recorded too.
	require.Len(t, app.challengeSnapshot(), 1)
}

func TestServeHTTP_V2ServedDispositionAndEmptyHost(t *testing.T) {
	app := &fakeApp{modeV2: true}
	h := &StatsHandler{app: app}

	r := newRequestWithReplacer("GET", "/api", "100", upstreamSelected("10.0.0.1:8080"))
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(200)))

	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, dispServed, evs[0].Disposition)
	require.Equal(t, "", evs[0].Host, "served rows with a vhost_id omit host")
	require.True(t, evs[0].V2)
}

func TestServeHTTP_V2NoChallengeNoVhost_DoesNotLog(t *testing.T) {
	// mode_v2: a plain no-route request (no vhost_id, no challenge outcome)
	// must still be dropped — logging it under vhost_id=0 would pollute the
	// per-vhost log. Only terminal challenges relax the vhost gate.
	app := &fakeApp{modeV2: true}
	h := &StatsHandler{app: app}

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(404)))
	require.Empty(t, app.reqEventSnapshot())
}

// A 103 Early Hints forwarded by reverse_proxy must not finalize the
// response: the later real status has to reach the client and the stats row.
func TestRecorder_103EarlyHintsDoesNotFinalizeStatus(t *testing.T) {
	var got *recorder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &recorder{ResponseWriter: w, status: 200}
		rec.Header().Set("Link", "</x.css>; rel=preload; as=style")
		rec.WriteHeader(http.StatusEarlyHints)
		rec.Header().Set("Location", "/login")
		rec.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = rec.Write(nil)
		got = rec
	}))
	defer srv.Close()

	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("client status: want 307, got %d", res.StatusCode)
	}
	if res.Header.Get("Location") != "/login" {
		t.Fatalf("Location lost: %q", res.Header.Get("Location"))
	}
	if got.status != http.StatusTemporaryRedirect || !got.wrote {
		t.Fatalf("recorder: want status=307 wrote=true, got status=%d wrote=%v", got.status, got.wrote)
	}
}

// Same thing through a real reverse proxy (Go's httputil forwards 1xx the
// same way Caddy's reverse_proxy does), with a 500 to show it is not
// redirect-specific.
func TestRecorder_103ThroughReverseProxyPreservesFinalStatus(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	rp := httputil.NewSingleHostReverseProxy(u)

	var got *recorder
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &recorder{ResponseWriter: w, status: 200}
		rp.ServeHTTP(rec, r)
		got = rec
	}))
	defer edge.Close()

	res, err := http.Get(edge.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("client status: want 500, got %d", res.StatusCode)
	}
	if got.status != http.StatusInternalServerError {
		t.Fatalf("recorder.status: want 500, got %d", got.status)
	}
}

// 101 Switching Protocols is a final status in Go's HTTP stack (the
// WebSocket upgrade path), not an informational one — the 1xx-passthrough
// guard must not swallow it.
func TestRecorder_101SwitchingProtocolsIsFinal(t *testing.T) {
	rec := &recorder{ResponseWriter: httptest.NewRecorder(), status: 200}
	rec.WriteHeader(http.StatusSwitchingProtocols)
	if rec.status != http.StatusSwitchingProtocols || !rec.wrote {
		t.Fatalf("101 must finalize: got status=%d wrote=%v", rec.status, rec.wrote)
	}
}
