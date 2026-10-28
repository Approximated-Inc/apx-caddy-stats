package apxstats

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

func admissionReq(method, target string, headers ...string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

func navigation(target string) *http.Request {
	return admissionReq("GET", target, "Sec-Fetch-Mode", "navigate", "Accept", "text/html,application/xhtml+xml")
}

var okNext = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

func serveAdmission(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	require.NoError(t, AdmissionHandler{}.ServeHTTP(w, r, okNext))
	return w
}

// C1: classes, and streams release their slot once the response streams.
func TestAdmissionClassify(t *testing.T) {
	cases := []struct {
		r    *http.Request
		want int
	}{
		{admissionReq("GET", "/__apx_verify/widget.js"), admitP0},
		{admissionReq("POST", "/__apx_challenge/verify"), admitP0},
		{admissionReq("GET", "/.well-known/acme-challenge/tok"), admitP0},
		{admissionReq("GET", "/healthy"), admitP0},
		{admissionReq("GET", "/apxflyhealthcheck?x=1"), admitP0},
		{navigation("/pricing"), admitP1},
		{admissionReq("GET", "/docs", "Sec-Fetch-Dest", "document"), admitP1},
		{admissionReq("GET", "/", "Accept", "text/html"), admitP1},
		{admissionReq("POST", "/login", "Accept", "text/html"), admitP2},
		{admissionReq("GET", "/api/items"), admitP2},
		{admissionReq("POST", "/app.js"), admitP2},
		{admissionReq("GET", "/app.js?v=1"), admitP3},
		{admissionReq("HEAD", "/img/logo.PNG"), admitP3},
	}
	for _, c := range cases {
		require.Equal(t, c.want, classifyAdmission(c.r), c.r.Method+" "+c.r.URL.String())
	}

	resetOverload(t)
	setOverload(t, &OverloadConfig{Admission: &AdmissionConfig{Mode: "enforce"}}, 2)
	admissionLimitNow.Store(100)
	for _, c := range []struct {
		r      *http.Request
		stream func(http.ResponseWriter)
	}{
		{admissionReq("GET", "/ws", "Connection", "Upgrade", "Upgrade", "websocket"),
			func(w http.ResponseWriter) { w.WriteHeader(http.StatusSwitchingProtocols) }},
		{admissionReq("GET", "/events", "Accept", "text/event-stream"),
			func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: 1\n\n"))
			}},
		{admissionReq("CONNECT", "/ws"), func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }},
	} {
		var before, after int64 = -1, -1
		require.NoError(t, AdmissionHandler{}.ServeHTTP(httptest.NewRecorder(), c.r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			before = admissionInflight.Load()
			c.stream(w)
			after = admissionInflight.Load()
			return nil
		})))
		require.EqualValues(t, 1, before, "counted until the response streams: %s", c.r.URL)
		require.Zero(t, after, "released once it streams: %s", c.r.URL)
		require.Zero(t, admissionInflight.Load(), "released once: %s", c.r.URL)
	}
}

// The stream headers are the client's: claiming one buys no pass. A slow
// request that only says Accept: text/event-stream is counted until done and
// shed at the cap like any other.
func TestAdmissionStreamHeadersAreNoBypass(t *testing.T) {
	resetOverload(t)
	setOverload(t, &OverloadConfig{Admission: &AdmissionConfig{Mode: "enforce", HardLimit: 4}}, 0)
	sse := func() *http.Request { return admissionReq("GET", "/api/slow", "Accept", "text/event-stream;q=0") }
	var during int64 = -1
	require.NoError(t, AdmissionHandler{}.ServeHTTP(httptest.NewRecorder(), sse(), caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
		during = admissionInflight.Load()
		return nil
	})))
	require.EqualValues(t, 1, during, "a JSON response keeps its slot")
	require.Zero(t, admissionInflight.Load())

	admissionInflight.Store(4)
	require.Equal(t, http.StatusServiceUnavailable, serveAdmission(t, sse()).Code)
	ws := admissionReq("GET", "/api/slow", "Upgrade", "websocket")
	require.Equal(t, http.StatusServiceUnavailable, serveAdmission(t, ws).Code)
	require.EqualValues(t, 2, overloadCounts.shed[admitP2].Load())
}

// C2: level 2 thresholds against the adaptive limit.
func TestAdmissionLevel2Thresholds(t *testing.T) {
	resetOverload(t)
	setOverload(t, &OverloadConfig{Admission: &AdmissionConfig{Mode: "enforce"}}, 2)
	admissionLimitNow.Store(10)

	admissionInflight.Store(6)
	w := serveAdmission(t, admissionReq("GET", "/app.js"))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	ra, err := strconv.Atoi(w.Header().Get("Retry-After"))
	require.NoError(t, err)
	require.True(t, ra >= 1 && ra <= 3, "Retry-After %d", ra)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, "1", w.Header().Get("apx-overload"))
	require.Empty(t, w.Header().Get("Connection"), "keep the connection")
	require.Equal(t, http.StatusOK, serveAdmission(t, navigation("/")).Code)
	require.Equal(t, http.StatusOK, serveAdmission(t, admissionReq("GET", "/api")).Code, "P2 sheds at L")
	require.EqualValues(t, 6, admissionInflight.Load(), "shed and admitted requests both release their slot")

	admissionInflight.Store(16)
	require.Equal(t, http.StatusServiceUnavailable, serveAdmission(t, navigation("/")).Code)
	require.Equal(t, http.StatusServiceUnavailable, serveAdmission(t, admissionReq("GET", "/api")).Code)
	require.Equal(t, http.StatusOK, serveAdmission(t, admissionReq("GET", "/__apx_verify/challenge")).Code)
	require.EqualValues(t, 1, overloadCounts.shed[admitP1].Load())
	require.EqualValues(t, 1, overloadCounts.shed[admitP2].Load())
	require.EqualValues(t, 1, overloadCounts.shed[admitP3].Load())
	require.Zero(t, overloadCounts.shed[admitP0].Load())
}

// C3: below level 2 a slow origin is not a reason to shed.
func TestAdmissionLevel0SlowOriginAdmitsAll(t *testing.T) {
	resetOverload(t)
	setOverload(t, &OverloadConfig{Admission: &AdmissionConfig{Mode: "enforce", HardLimit: 2000}}, 0)
	admissionLimitNow.Store(8)
	release := make(chan struct{})
	var started, wg sync.WaitGroup
	codes := make(chan int, 1000)
	for i := 0; i < 1000; i++ {
		started.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			_ = AdmissionHandler{}.ServeHTTP(w, admissionReq("GET", "/app.js"), caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				started.Done()
				<-release
				w.WriteHeader(http.StatusOK)
				return nil
			}))
			if w.Code != http.StatusOK {
				started.Done()
			}
			codes <- w.Code
		}()
	}
	started.Wait()
	close(release)
	wg.Wait()
	close(codes)
	for c := range codes {
		require.Equal(t, http.StatusOK, c)
	}
	require.Zero(t, admissionInflight.Load())
}

// C4: the hard cap sheds at any level in enforce mode; observe only counts.
func TestAdmissionHardCap(t *testing.T) {
	resetOverload(t)
	setOverload(t, &OverloadConfig{Admission: &AdmissionConfig{Mode: "enforce", HardLimit: 4}}, 0)
	admissionInflight.Store(4)
	require.Equal(t, http.StatusServiceUnavailable, serveAdmission(t, admissionReq("GET", "/app.js")).Code)
	require.True(t, hardCapHit.Load())
	require.Equal(t, http.StatusOK, serveAdmission(t, navigation("/")).Code, "P1 sheds at 1.25 × hard")
	admissionInflight.Store(5)
	require.Equal(t, http.StatusServiceUnavailable, serveAdmission(t, navigation("/")).Code)

	setOverload(t, &OverloadConfig{Admission: &AdmissionConfig{Mode: "observe", HardLimit: 4}}, 2)
	admissionLimitNow.Store(2)
	hardCapHit.Store(false)
	admissionInflight.Store(9)
	require.Equal(t, http.StatusOK, serveAdmission(t, admissionReq("GET", "/app.js")).Code)
	require.Equal(t, http.StatusOK, serveAdmission(t, navigation("/")).Code)
	require.EqualValues(t, 2, overloadCounts.wouldShed.Load())
	require.False(t, hardCapHit.Load())
	require.EqualValues(t, 9, admissionInflight.Load())
}

// C5: in-flight is released after an error and after a panic.
func TestAdmissionReleasesOnErrorAndPanic(t *testing.T) {
	resetOverload(t)
	setOverload(t, &OverloadConfig{Admission: &AdmissionConfig{Mode: "enforce"}}, 2)
	admissionLimitNow.Store(100)
	boom := errors.New("upstream")
	for _, level := range []int32{0, 2} {
		overload.level.Store(level)
		err := AdmissionHandler{}.ServeHTTP(httptest.NewRecorder(), admissionReq("GET", "/x"), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return boom }))
		require.ErrorIs(t, err, boom)
		require.Zero(t, admissionInflight.Load())
		func() {
			defer func() { require.NotNil(t, recover()) }()
			_ = AdmissionHandler{}.ServeHTTP(httptest.NewRecorder(), admissionReq("GET", "/x"), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { panic("handler") }))
		}()
		require.Zero(t, admissionInflight.Load(), "level %d", level)
	}
}

type nopWriter struct{ h http.Header }

func (n *nopWriter) Header() http.Header         { return n.h }
func (n *nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (n *nopWriter) WriteHeader(int)             {}

// C6: no allocation to admit; at most two to shed.
func TestAdmissionAllocs(t *testing.T) {
	resetOverload(t)
	setOverload(t, &OverloadConfig{Admission: &AdmissionConfig{Mode: "enforce"}}, 0)
	r := admissionReq("GET", "/static/APP.JS?v=1", "Accept", "*/*")
	w := &nopWriter{h: http.Header{}}
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	h := AdmissionHandler{}
	require.Zero(t, testing.AllocsPerRun(200, func() { _ = h.ServeHTTP(w, r, next) }), "admit path")

	overload.level.Store(2)
	admissionLimitNow.Store(10)
	admissionInflight.Store(9)
	shed := testing.AllocsPerRun(200, func() { _ = h.ServeHTTP(w, r, next) })
	require.LessOrEqual(t, shed, 2.0, "shed path")
	require.Equal(t, "503 node overloaded, retry in a moment\n", string(shedBody))
}

// C7: the adaptive limit.
func TestAdaptiveLimit(t *testing.T) {
	require.Equal(t, 20, adaptiveLimit(20, time.Second, 8, 1000))
	require.Equal(t, 21, adaptiveLimit(20.2, time.Second, 8, 1000))
	require.Equal(t, 8, adaptiveLimit(2, time.Second, 8, 1000))
	require.Equal(t, 300, adaptiveLimit(5000, time.Second, 8, 300))
	require.Equal(t, 480, adaptiveLimit(200, 2400*time.Millisecond, 8, 1000))

	var c completionRate
	require.Zero(t, c.sample(0, time.Second))
	got := 0.0
	for i := 1; i <= 120; i++ {
		got = c.sample(uint64(i*20), time.Second)
	}
	require.InDelta(t, 20, got, 0.1, "10 s EWMA converges on 20/s")
}

// The latency target follows the node's normal latency, learned at level 0
// only: an origin that always takes 1.2 s gets 2.4 s, so at level 2 P2 sheds
// once latency doubles, not merely because the origin is slow.
func TestLatencyTargetFollowsNormalLatency(t *testing.T) {
	var l latencyTarget
	require.Equal(t, time.Second, l.sample(0, 0, time.Second, true), "unknown is 1 s")
	n, ns := uint64(0), uint64(0)
	step := func(rate int, mean time.Duration, normal bool) time.Duration {
		n += uint64(rate)
		ns += uint64(rate) * uint64(mean)
		return l.sample(n, ns, time.Second, normal)
	}
	var got time.Duration
	for i := 0; i < 600; i++ {
		got = step(200, 1200*time.Millisecond, true)
	}
	require.InDelta(t, 2400*time.Millisecond, got, float64(20*time.Millisecond))
	for i := 0; i < 600; i++ {
		got = step(200, 5*time.Second, false) // overloaded: not learned
	}
	require.InDelta(t, 2400*time.Millisecond, got, float64(20*time.Millisecond))
	for i := 0; i < 600; i++ {
		got = step(200, 50*time.Millisecond, true)
	}
	require.Equal(t, time.Second, got, "never below 1 s")
	for i := 0; i < 3000; i++ {
		got = step(200, time.Minute, true)
	}
	require.Equal(t, 10*time.Second, got, "never above 10 s")
}

// Shed requests never complete. The rate behind the limit must not follow
// the throughput shedding removed: a drop from 200/s to 20/s admitted keeps
// the limit near 200 for tens of seconds instead of ratcheting to min_limit.
func TestCompletionRateHoldsPeakWhileShedding(t *testing.T) {
	var c completionRate
	total := uint64(0)
	var got float64
	for i := 0; i < 120; i++ {
		total += 200
		got = c.sample(total, time.Second)
	}
	require.InDelta(t, 200, got, 1)
	for i := 0; i < 10; i++ {
		total += 20
		got = c.sample(total, time.Second)
	}
	require.Greater(t, got, 160.0, "decays with a 60 s time constant")
	for i := 0; i < 600; i++ {
		total += 20
		got = c.sample(total, time.Second)
	}
	require.InDelta(t, 20, got, 1, "follows a lasting drop")
}
