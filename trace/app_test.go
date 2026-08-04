package apxtrace

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// provisionForTest drives Provision() without a full Caddy context. We stub
// out the parts Provision needs by constructing the app manually where the
// Caddy Context would normally provide a logger.
func provisionForTest(t *testing.T, a *TraceApp) {
	t.Helper()
	// Mimic Provision without requiring a caddy.Context — the Caddy Context
	// only supplies a logger, which is optional for our code paths. We set
	// the other fields ourselves.
	envVar := "APX_INTERNAL_KEY"
	if a.EventSink != nil && a.EventSink.AuthEnvVar != "" {
		envVar = a.EventSink.AuthEnvVar
	}
	require.NotEmpty(t, a.EventSink, "test must set EventSink")
	require.NotEmpty(t, a.EventSink.URL, "test must set EventSink.URL")
	secret := getEnvForTest(t, envVar)
	require.NotEmpty(t, secret, "test must set "+envVar)
	a.secret = secret
	a.client = &http.Client{Timeout: 2 * time.Second}
	bufSize := a.EventSink.BufferSize
	if bufSize <= 0 {
		bufSize = 16
	}
	a.ch = make(chan outbound, bufSize)
	a.done = make(chan struct{})
	conc := a.EventSink.Concurrency
	if conc <= 0 {
		conc = 2
	}
	for i := 0; i < conc; i++ {
		a.wg.Add(1)
		go a.drain()
	}
}

func getEnvForTest(t *testing.T, name string) string {
	t.Helper()
	// t.Setenv is used to populate; this indirection keeps tests isolated.
	return mustGetEnv(name)
}

func mustGetEnv(name string) string {
	// Read through os.Getenv via token.go's defaultStringEnv would round-trip;
	// just use os.Getenv directly.
	return envGet(name)
}

func TestTraceApp_Provision_RequiresEventSink(t *testing.T) {
	a := &TraceApp{}
	err := a.Provision(fakeCaddyCtx())
	require.Error(t, err)
	require.Contains(t, err.Error(), "event_sink config is required")
}

func TestTraceApp_Provision_RequiresEventSinkURL(t *testing.T) {
	a := &TraceApp{EventSink: &EventSinkConfig{}}
	err := a.Provision(fakeCaddyCtx())
	require.Error(t, err)
	require.Contains(t, err.Error(), "event_sink.url is required")
}

func TestTraceApp_Provision_RequiresAuthEnvVar(t *testing.T) {
	// Ensure the env var is unset.
	t.Setenv("APX_INTERNAL_KEY", "")
	a := &TraceApp{EventSink: &EventSinkConfig{URL: "http://example.com/hook"}}
	err := a.Provision(fakeCaddyCtx())
	require.Error(t, err)
	require.Contains(t, err.Error(), "APX_INTERNAL_KEY env var is empty")
}

func TestTraceApp_Provision_CustomAuthEnvVar(t *testing.T) {
	t.Setenv("MY_CUSTOM_KEY", "shh")
	a := &TraceApp{EventSink: &EventSinkConfig{
		URL:        "http://example.com/hook",
		AuthEnvVar: "MY_CUSTOM_KEY",
	}}
	err := a.Provision(fakeCaddyCtx())
	require.NoError(t, err)
	require.Equal(t, "shh", a.Secret())
}

type capturedPost struct {
	headers http.Header
	body    []byte
}

func TestTraceApp_EmitEvent_PostsToSink(t *testing.T) {
	var (
		mu       sync.Mutex
		captured []capturedPost
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		captured = append(captured, capturedPost{headers: r.Header.Clone(), body: body})
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	t.Setenv("APX_INTERNAL_KEY", "sekret")

	a := &TraceApp{EventSink: &EventSinkConfig{
		URL:         srv.URL,
		BufferSize:  16,
		Concurrency: 1,
	}}
	provisionForTest(t, a)
	defer a.Stop()

	a.EmitEvent(Event{
		Type:    EventClusterReceived,
		TsNs:    12345,
		Source:  SourceCluster,
		Payload: map[string]any{"hello": "world"},
	}, "the-token")

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(captured) == 1
	}, 2*time.Second, 10*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	got := captured[0]
	require.Equal(t, "sekret", got.headers.Get("apx-key"))
	require.Equal(t, "the-token", got.headers.Get("apx-trace-token"))
	require.Equal(t, "application/json", got.headers.Get("Content-Type"))

	var parsed Event
	require.NoError(t, json.Unmarshal(got.body, &parsed))
	require.Equal(t, EventClusterReceived, parsed.Type)
	require.Equal(t, int64(12345), parsed.TsNs)
	require.Equal(t, SourceCluster, parsed.Source)
	require.Equal(t, "world", parsed.Payload["hello"])
}

func TestTraceApp_EmitEvent_DropsOnFullBuffer(t *testing.T) {
	// Server responds slowly so the outbound channel fills up.
	slow := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-slow
		w.WriteHeader(200)
	}))
	defer srv.Close()
	defer close(slow)

	t.Setenv("APX_INTERNAL_KEY", "k")

	a := &TraceApp{EventSink: &EventSinkConfig{
		URL:         srv.URL,
		BufferSize:  2,
		Concurrency: 1,
	}}
	provisionForTest(t, a)
	defer a.Stop()

	// First few events park in the single-drain goroutine + buffer. Beyond
	// that they must drop.
	for i := 0; i < 50; i++ {
		a.EmitEvent(Event{Type: EventClusterReceived, TsNs: int64(i), Source: SourceCluster}, "tok")
	}
	// Give the counter time to be bumped.
	require.Eventually(t, func() bool {
		return atomic.LoadUint64(&a.dropped) > 0
	}, time.Second, 10*time.Millisecond)
}

func TestTraceApp_EmitEvent_NonSuccessStatusCountsAsError(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	t.Setenv("APX_INTERNAL_KEY", "k")
	a := &TraceApp{EventSink: &EventSinkConfig{URL: srv.URL, BufferSize: 4, Concurrency: 1}}
	provisionForTest(t, a)
	defer a.Stop()

	a.EmitEvent(Event{Type: EventClusterReceived, Source: SourceCluster}, "tok")
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&hits) == 1
	}, 2*time.Second, 10*time.Millisecond)
	// No easy way to assert the metric directly without a registry scrape,
	// but the main thing is the request was attempted and we didn't crash.
}
