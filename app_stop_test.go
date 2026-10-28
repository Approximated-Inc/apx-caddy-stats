package apxstats

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

// A7: a real Caddy /load against a hung ingest. Each load stops the old
// apx_stats app, whose final batch can't ship. Before the fix each load took
// ≈ 93 s with these settings (10 s timeout, 7 shutdown retries).
func TestCaddyReloadNotStalledByHungIngest(t *testing.T) {
	ing := newHungIngest(t)
	addr := freeLoopbackAddr(t)
	config := func(grace string) []byte {
		raw, err := json.Marshal(map[string]any{
			"admin":   map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
			"storage": map[string]any{"module": "file_system", "root": t.TempDir()},
			"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
			"apps": map[string]any{
				"apx_stats": map[string]any{
					"proxy_server_id": 89,
					"ingest": map[string]any{
						"url":               ing.srv.URL,
						"auth_token":        "test-token",
						"flush_interval_ms": 3_600_000,
						"timeout_ms":        10_000,
						// Short only so this test frees its retired slots
						// quickly; the wait under test is stop_wait_ms (default).
						"shutdown_deadline_ms": 1_500,
					},
				},
				"http": map[string]any{
					"grace_period": grace,
					"servers": map[string]any{"edge": map[string]any{
						"listen":          []string{addr},
						"automatic_https": map[string]any{"disable": true},
						"routes": []any{map[string]any{"handle": []any{
							map[string]any{"handler": "apx_stats"},
							map[string]any{"handler": "vars", "vhost_id": "101"},
							map[string]any{"handler": "static_response", "status_code": 200},
						}}},
					}},
				},
			},
		})
		require.NoError(t, err)
		return raw
	}
	require.NoError(t, caddy.Load(config("1s"), true))
	t.Cleanup(func() {
		_ = caddy.Stop()
		require.Eventually(t, func() bool { return len(retiredShipSlots) == 0 }, 5*time.Second, 20*time.Millisecond)
	})
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	hit := func() {
		resp, err := client.Get("http://" + addr + "/")
		require.NoError(t, err)
		_ = resp.Body.Close()
	}

	for i, grace := range []string{"2s", "3s"} {
		hit() // a counter row, so the stopping app has a final batch to ship
		start := time.Now()
		require.NoError(t, caddy.Load(config(grace), true))
		require.Less(t, time.Since(start), 3*time.Second, "load %d", i+1)
	}
	require.GreaterOrEqual(t, ing.seen.Load(), int32(2), "each stopped app attempted its final batch")
}

// hungIngest blocks every request until the client gives up or the test
// ends. It records how many POSTs it saw and the peak concurrency.
type hungIngest struct {
	srv     *httptest.Server
	release chan struct{}
	seen    atomic.Int32
	active  atomic.Int32
	peak    atomic.Int32
	entered chan struct{}
	once    sync.Once
}

func newHungIngest(t *testing.T) *hungIngest {
	t.Helper()
	h := &hungIngest{release: make(chan struct{}), entered: make(chan struct{})}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // lets the server notice the client hanging up
		h.seen.Add(1)
		n := h.active.Add(1)
		defer h.active.Add(-1)
		for p := h.peak.Load(); n > p && !h.peak.CompareAndSwap(p, n); p = h.peak.Load() {
		}
		h.once.Do(func() { close(h.entered) })
		select {
		case <-h.release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(h.release)
		h.srv.Close()
	})
	return h
}

// realisticShutdownConfig mirrors production defaults: 10 s client timeout
// and 7 shutdown retries (≈ 93 s against a hung ingest before this fix).
func realisticShutdownConfig(a *StatsApp) {
	a.cfg.flushInterval = time.Hour
	a.cfg.shutdownMaxRetries = 7
	a.cfg.maxRetries = 3
	a.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}}
}

// finishShipper cuts any background shutdown ship and waits for shipLoop,
// so a hung test never holds a process-wide retired slot into the next one.
func finishShipper(t *testing.T, a *StatsApp) {
	t.Helper()
	if a.shutdownReady != nil {
		select {
		case <-a.shutdownReady:
			a.shutdownCancel()
		default:
		}
	}
	if a.shipDone != nil {
		select {
		case <-a.shipDone:
		case <-time.After(5 * time.Second):
			t.Fatal("shipLoop did not exit")
		}
	}
}

func stopWithin(t *testing.T, a *StatsApp, guard time.Duration) time.Duration {
	t.Helper()
	done := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		require.NoError(t, a.Stop())
		done <- time.Since(start)
	}()
	select {
	case d := <-done:
		return d
	case <-time.After(guard):
		t.Fatalf("Stop did not return within %s", guard)
		return 0
	}
}

// A1: a hung ingest can no longer stall Stop (and so a Caddy /load).
func TestStopHungIngestReturnsQuickly(t *testing.T) {
	ing := newHungIngest(t)
	a := newTestApp(t, ing.srv.URL, "key")
	realisticShutdownConfig(a)
	defer finishShipper(t, a)
	a.Record(Key{VhostID: 1, Status: 200}, CounterDelta{})
	require.NoError(t, a.Start())

	d := stopWithin(t, a, 5*time.Second)
	require.Less(t, d, 2500*time.Millisecond)
	require.EqualValues(t, 1, ing.seen.Load(), "the final batch was attempted")
}

// A2: a tick POST in flight on a hung ingest is cut by Stop and its body is
// retried under the shutdown deadline, not dropped and not waited on.
func TestStopCancelsInFlightTickAndRequeuesIt(t *testing.T) {
	capture, posts := captureServer(t, 200)
	defer capture.Close()
	entered := make(chan struct{})
	var first atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if first.CompareAndSwap(false, true) {
			_, _ = io.Copy(io.Discard, r.Body)
			close(entered)
			<-r.Context().Done() // the tick POST hangs until cancelled
			return
		}
		capture.Config.Handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	a := newTestApp(t, srv.URL, "key")
	realisticShutdownConfig(a)
	defer finishShipper(t, a)
	a.cfg.flushInterval = 20 * time.Millisecond
	a.Record(Key{VhostID: 1, Status: 200}, CounterDelta{})
	require.NoError(t, a.Start())
	<-entered
	a.Record(Key{VhostID: 2, Status: 200}, CounterDelta{})

	d := stopWithin(t, a, 5*time.Second)
	require.Less(t, d, 2500*time.Millisecond)
	vhosts := map[float64]int{}
	for _, p := range posts() {
		for _, row := range p.rows {
			if row["request_count"] != nil {
				vhosts[row["vhost_id"].(float64)]++
			}
		}
	}
	require.Equal(t, map[float64]int{1: 1, 2: 1}, vhosts, "tick body requeued and final batch shipped before Stop returned")
}

// A3: a slow-but-healthy ingest still gets the final batch before Stop
// returns, so graceful shutdown keeps its no-loss behaviour.
func TestStopWaitsForHealthySlowIngest(t *testing.T) {
	capture, posts := captureServer(t, 200)
	defer capture.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		capture.Config.Handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	a := newTestApp(t, srv.URL, "key")
	realisticShutdownConfig(a)
	defer finishShipper(t, a)
	a.Record(Key{VhostID: 7, Status: 200}, CounterDelta{})
	require.NoError(t, a.Start())

	stopWithin(t, a, 5*time.Second)
	require.Len(t, posts(), 1, "final batch received before Stop returned")
	require.Zero(t, a.Dropped())
}

// A4: the shutdown deadline cuts a hung POST: rows are counted dropped
// promptly and no goroutine outlives the deadline.
func TestShutdownDeadlineCutsHungShip(t *testing.T) {
	ing := newHungIngest(t)
	a := newTestApp(t, ing.srv.URL, "key")
	realisticShutdownConfig(a)
	a.cfg.shutdownDeadline = 200 * time.Millisecond
	a.cfg.stopWait = 50 * time.Millisecond
	tr := a.client.Transport.(*http.Transport)
	runtime.GC()
	baseline := runtime.NumGoroutine()
	a.Record(Key{VhostID: 1, Status: 200}, CounterDelta{})
	require.NoError(t, a.Start())
	stopWithin(t, a, 5*time.Second)

	require.Eventually(t, func() bool { return a.Dropped() == 1 }, 350*time.Millisecond, 5*time.Millisecond,
		"dropped by ≈ the 200 ms deadline")
	select {
	case <-a.shipDone:
	case <-time.After(time.Second):
		t.Fatal("shipLoop outlived the shutdown deadline")
	}
	tr.CloseIdleConnections()
	require.Eventually(t, func() bool {
		n := runtime.NumGoroutine()
		return n <= baseline+1
	}, time.Second, 10*time.Millisecond, "goroutines back to baseline")
}

// A5: retired shipping is bounded process-wide: five generations stopped
// back to back on a hung ingest never put more than two POSTs in flight.
func TestRetiredShippingBoundedProcessWide(t *testing.T) {
	ing := newHungIngest(t)
	apps := make([]*StatsApp, 5)
	for i := range apps {
		a := newTestApp(t, ing.srv.URL, "key")
		realisticShutdownConfig(a)
		a.cfg.stopWait = 20 * time.Millisecond
		apps[i] = a
		defer finishShipper(t, a)
	}
	for i, a := range apps {
		a.Record(Key{VhostID: uint32(i + 1), Status: 200}, CounterDelta{})
		require.NoError(t, a.Start())
		stopWithin(t, a, 5*time.Second)
	}
	time.Sleep(200 * time.Millisecond)
	require.LessOrEqual(t, ing.peak.Load(), int32(2))
	busy := 0
	for _, a := range apps {
		if a.Dropped() == 1 {
			busy++
		}
	}
	require.Equal(t, 3, busy, "generations without a slot drop and count")
}

// A6: a full ship queue drops the oldest job; the newer two ship.
func TestShipQueueDropsOldest(t *testing.T) {
	server, posts := captureServer(t, 200)
	defer server.Close()
	a := newTestApp(t, server.URL, "key")
	var bodies [][]byte
	for i := 1; i <= 3; i++ {
		a.Record(Key{VhostID: uint32(i), Status: 200}, CounterDelta{})
		body, rows, ok := a.drainAndEncode(false)
		require.True(t, ok)
		require.Equal(t, 1, rows)
		bodies = append(bodies, body)
	}
	a.shipQ = newShipQueue()
	for _, b := range bodies {
		a.enqueueShip(&shipJob{body: b, rows: 1})
	}
	require.EqualValues(t, 1, a.Dropped())

	a.shipDone = make(chan struct{})
	a.shutdownReady = make(chan struct{})
	a.tickCtx, a.tickCancel = context.WithCancel(context.Background())
	defer a.tickCancel()
	go a.shipLoop()
	a.shipQ.close()
	<-a.shipDone
	var got []float64
	for _, p := range posts() {
		for _, row := range p.rows {
			if row["request_count"] != nil {
				got = append(got, row["vhost_id"].(float64))
			}
		}
	}
	require.Equal(t, []float64{2, 3}, got)
}
