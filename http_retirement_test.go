package apxstats

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

func TestHTTPRetirementHeldRequestDeliveredAfterStop(t *testing.T) {
	for _, modeV2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "v1", true: "v2"}[modeV2], func(t *testing.T) {
			server, posts := captureServer(t, 200)
			defer server.Close()
			a := newTestApp(t, server.URL, "old-key", func(a *StatsApp) {
				a.ProxyServerIDValue = 41
				a.hashSalt = "old-salt"
				a.machineID = "old-machine"
				a.DefenseExemptionTelemetry = true
				a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: modeV2, MaxRows: 100}
			})
			require.NoError(t, a.Start())
			held, release, completed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			h := &StatsHandler{app: a}
			go func() {
				r := newRequestWithReplacer("GET", "/held", "100", upstreamSelected("u:80"))
				completed <- h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					close(held)
					<-release
					return nextHandler(200).ServeHTTP(w, r)
				}))
			}()
			<-held
			require.NoError(t, a.Stop()) // must finish while the request is still held
			close(release)
			require.NoError(t, <-completed)
			awaitHTTPRetirementIdle(t, a)
			var events, counters int
			for _, post := range posts() {
				require.Equal(t, "41", post.headers.Get(proxyServerIDHeader))
				for _, row := range post.rows {
					require.Equal(t, float64(41), row["proxy_server_id"])
					if row["_type"] == "request_event" {
						events++
						require.Equal(t, "/held", row["path"])
						if modeV2 {
							require.Equal(t, "old-machine", row["machine_id"])
							require.Contains(t, row, "disposition")
						} else {
							require.NotContains(t, row, "disposition")
							require.NotContains(t, row, "ts_ms")
						}
					}
					if row["request_count"] != nil {
						counters += int(row["request_count"].(float64))
					}
				}
			}
			require.Equal(t, 1, events)
			require.Equal(t, 1, counters)
		})
	}
}

func awaitHTTPRetirementIdle(t *testing.T, a *StatsApp) {
	t.Helper()
	a.httpDeliveryMu.Lock()
	done := a.httpDeliveryDone
	a.httpDeliveryMu.Unlock()
	require.NotNil(t, done)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("retired HTTP worker did not exit")
	}
}

func TestHTTPRetirementStopRecordHandshake(t *testing.T) {
	capture, posts := captureServer(t, 200)
	defer capture.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Do(func() { close(entered); <-release })
		capture.Config.Handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	a := newTestApp(t, server.URL, "key")
	a.cfg.flushInterval = time.Hour
	a.Record(Key{VhostID: 100, Status: 200}, CounterDelta{})
	require.NoError(t, a.Start())
	stopped := make(chan error, 1)
	go func() { stopped <- a.Stop() }()
	<-entered // old final drain is in flight, before retirement's mutex handshake
	a.Record(Key{VhostID: 101, Status: 200}, CounterDelta{})
	a.finishHTTPRecord()
	close(release)
	require.NoError(t, <-stopped)
	awaitHTTPRetirementIdle(t, a)
	total := 0
	for _, post := range posts() {
		for _, row := range post.rows {
			if row["request_count"] != nil {
				total += int(row["request_count"].(float64))
			}
		}
	}
	require.Equal(t, 2, total)
}

func TestHTTPRetirementCoalescesAndRestartsWithoutBlockingRequests(t *testing.T) {
	capture, posts := captureServer(t, 200)
	defer capture.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	var active, maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for prior := maximum.Load(); n > prior; prior = maximum.Load() {
			if maximum.CompareAndSwap(prior, n) {
				break
			}
		}
		first.Do(func() { close(entered); <-release })
		capture.Config.Handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	a := newTestApp(t, server.URL, "key", func(a *StatsApp) {
		a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: true, MaxRows: 1000}
	})
	require.NoError(t, a.Stop())
	awaitHTTPRetirementIdle(t, a)
	h := &StatsHandler{app: a}
	request := func(path string) {
		r := newRequestWithReplacer("GET", path, "100", upstreamSelected("u:80"))
		require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, nextHandler(200)))
	}
	request("/first")
	<-entered // worker held in delivery; completions must not wait for it
	var writers sync.WaitGroup
	for i := 0; i < 100; i++ {
		writers.Add(1)
		go func(i int) { defer writers.Done(); request(fmt.Sprintf("/coalesced/%d", i)) }(i)
	}
	writers.Wait()
	a.httpDeliveryMu.Lock()
	require.True(t, a.httpDeliveryRunning)
	require.True(t, a.httpDeliveryPending)
	a.httpDeliveryMu.Unlock()
	close(release)
	awaitHTTPRetirementIdle(t, a)
	request("/restart") // starts again after the completed worker's idle handshake
	awaitHTTPRetirementIdle(t, a)
	events, counters := map[string]int{}, 0
	for _, post := range posts() {
		for _, row := range post.rows {
			if row["_type"] == "request_event" {
				events[row["path"].(string)]++
			}
			if row["request_count"] != nil {
				counters += int(row["request_count"].(float64))
			}
		}
	}
	require.Len(t, events, 102)
	for _, count := range events {
		require.Equal(t, 1, count)
	}
	require.Equal(t, 102, counters)
	require.Equal(t, int32(1), maximum.Load())
}

func TestHTTPRetirementDoesNotDrainOtherTracksOrUseSuccessor(t *testing.T) {
	server, posts := captureServer(t, 200)
	defer server.Close()
	a := newTestApp(t, server.URL, "old-key", func(a *StatsApp) {
		a.ProxyServerIDValue = 41
		a.hashSalt = "old-salt"
		a.machineID = "old-machine"
		a.DefensePolicyEvidenceV2 = true
		a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: true, MaxRows: 100}
	})
	require.NoError(t, a.Stop())
	awaitHTTPRetirementIdle(t, a)
	a.l4SniMap[L4SniKey{SNI: "old.test"}] = &l4SniCounter{ConnectionCount: 1}
	a.l4IpPrefix["192.0.2.0/24"] = 1
	a.l4Blocks = map[l4BlockKey]uint64{{IP: "192.0.2.1", Reason: "ip"}: 1}
	a.fpMap = map[fingerprintKey]*fingerprintCounter{{JA4: "fp"}: {ConnectionCount: 1}}
	a.fpIpMap = map[fingerprintIpKey]*fingerprintCounter{{JA4: "fp", IP: "192.0.2.1"}: {ConnectionCount: 1}}
	a.corazaEvents = []corazaDetection{{RuleID: 942100}}
	successor := newTestApp(t, "http://unused", "new-key", func(a *StatsApp) { a.ProxyServerIDValue = 99; a.hashSalt = "new-salt"; a.machineID = "new-machine" })
	original := corazaApp.Load()
	corazaApp.Store(successor)
	defer corazaApp.Store(original)
	capture := evidenceHandler(t, `{"mode":"capture","http_var":"e_http"}`)
	h := &StatsHandler{app: a}
	r := newRequestWithReplacer("GET", "/old-evidence", "100", upstreamSelected("u:80"))
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		caddyhttp.SetVar(r.Context(), "e_http", "true")
		return capture.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			caddyhttp.SetVar(r.Context(), "e_http", "false")
			return nextHandler(200).ServeHTTP(w, r)
		}))
	})))
	awaitHTTPRetirementIdle(t, a)
	var foundEvent, foundCounter, foundUnique bool
	for _, post := range posts() {
		require.Equal(t, "41", post.headers.Get(proxyServerIDHeader))
		require.Equal(t, "old-key", post.headers.Get("apx-key"))
		for _, row := range post.rows {
			require.Equal(t, float64(41), row["proxy_server_id"])
			if row["_type"] == "request_event" {
				foundEvent = true
				require.Equal(t, "old-machine", row["machine_id"])
				require.Equal(t, true, row["defense_exempt"])
			}
			if row["request_count"] != nil {
				foundCounter = true
				require.Equal(t, true, row["defense_exempt"])
			}
			if row["client_hashes"] != nil {
				foundUnique = true
				require.Contains(t, row["client_hashes"], float64(ClientHash(clientIP(r), r.UserAgent(), "old-salt")))
			}
		}
	}
	require.True(t, foundEvent)
	require.True(t, foundCounter)
	require.True(t, foundUnique)
	require.Len(t, a.l4SniMap, 1)
	require.Len(t, a.l4IpPrefix, 1)
	require.Len(t, a.l4Blocks, 1)
	require.Len(t, a.fpMap, 1)
	require.Len(t, a.fpIpMap, 1)
	require.Len(t, a.corazaEvents, 1)
	require.Zero(t, successor.counterCount())
}

func TestHTTPRetirementTerminalRowsDelivered(t *testing.T) {
	server, posts := captureServer(t, 200)
	defer server.Close()
	a := newTestApp(t, server.URL, "key", func(a *StatsApp) {
		a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: true, MaxRows: 100}
	})
	require.NoError(t, a.Stop())
	awaitHTTPRetirementIdle(t, a)
	r := newRequestWithReplacer("GET", "/challenge", "", nil)
	caddyhttp.SetVar(r.Context(), "apx_challenge_outcome", "failed")
	h := &StatsHandler{app: a}
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, nextHandler(200)))
	awaitHTTPRetirementIdle(t, a)
	var event, challenge bool
	for _, post := range posts() {
		for _, row := range post.rows {
			if row["_type"] == "request_event" {
				event = true
				require.Equal(t, "/challenge", row["path"])
			}
			if row["_type"] == "challenge_attempt" {
				challenge = true
			}
		}
	}
	require.True(t, event)
	require.True(t, challenge)
}
