package apxtrace

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// fakeTraceApp is an in-memory AppRef used throughout the test suite.
type fakeTraceApp struct {
	mu     sync.Mutex
	events []Event
	tokens []string
	secret string
}

func newFakeTraceApp(secret string) *fakeTraceApp {
	return &fakeTraceApp{secret: secret}
}

func (f *fakeTraceApp) EmitEvent(evt Event, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, evt)
	f.tokens = append(f.tokens, token)
}

func (f *fakeTraceApp) Secret() string { return f.secret }

func (f *fakeTraceApp) eventCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func (f *fakeTraceApp) eventsCopy() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Event, len(f.events))
	copy(out, f.events)
	return out
}

// validTokenFor mints a valid trace token for the given secret + claims.
func validTokenFor(t *testing.T, secret string, payload TokenPayload) string {
	t.Helper()
	if payload.Exp == 0 {
		payload.Exp = time.Now().Add(time.Hour).Unix()
	}
	tok, err := SignToken(payload, secret)
	require.NoError(t, err)
	return tok
}

func nextHandlerOK() caddyhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
		return nil
	}
}

func TestTraceHandler_NoHeader_IsNoop(t *testing.T) {
	app := newFakeTraceApp("secret")
	h := &TraceHandler{
		headerName: "X-APX-Debug-Trace",
		app:        app,
		redactor:   DefaultRedactor(),
	}
	r := httptest.NewRequest("GET", "/foo", nil)
	w := httptest.NewRecorder()
	err := h.ServeHTTP(w, r, nextHandlerOK())
	require.NoError(t, err)
	require.Equal(t, 0, app.eventCount(), "no events should be emitted without header")
}

func TestTraceHandler_InvalidToken_IsNoop(t *testing.T) {
	app := newFakeTraceApp("secret")
	h := &TraceHandler{
		headerName: "X-APX-Debug-Trace",
		app:        app,
		redactor:   DefaultRedactor(),
	}
	r := httptest.NewRequest("GET", "/foo", nil)
	r.Header.Set("X-APX-Debug-Trace", "bogus-not-a-real-token")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandlerOK()))
	require.Equal(t, 0, app.eventCount())
}

func TestTraceHandler_WrongSecret_IsNoop(t *testing.T) {
	app := newFakeTraceApp("real-secret")
	h := &TraceHandler{
		headerName: "X-APX-Debug-Trace",
		app:        app,
		redactor:   DefaultRedactor(),
	}
	// Mint with a different secret — signature mismatch.
	tok := validTokenFor(t, "wrong-secret", TokenPayload{DebugRequestID: "dr-1", VhostID: 1})
	r := httptest.NewRequest("GET", "/foo", nil)
	r.Header.Set("X-APX-Debug-Trace", tok)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandlerOK()))
	require.Equal(t, 0, app.eventCount())
}

func TestTraceHandler_ExpiredToken_IsNoop(t *testing.T) {
	secret := "s"
	app := newFakeTraceApp(secret)
	h := &TraceHandler{
		headerName: "X-APX-Debug-Trace",
		app:        app,
		redactor:   DefaultRedactor(),
	}
	tok := validTokenFor(t, secret, TokenPayload{DebugRequestID: "dr-1", VhostID: 1, Exp: 1})
	r := httptest.NewRequest("GET", "/foo", nil)
	r.Header.Set("X-APX-Debug-Trace", tok)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandlerOK()))
	require.Equal(t, 0, app.eventCount())
}

type flusherWriter struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flusherWriter) Flush() { f.flushed = true; f.ResponseRecorder.Flush() }

type hijackerWriter struct {
	*httptest.ResponseRecorder
	hijackCalled bool
}

func (h *hijackerWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijackCalled = true
	// Return bogus values; we're only checking the delegation path.
	return nil, nil, nil
}

func TestResponseRecorder_FlushDelegatesToInner(t *testing.T) {
	inner := &flusherWriter{ResponseRecorder: httptest.NewRecorder()}
	rr := &responseRecorder{ResponseWriter: inner, status: 200}
	rr.Flush()
	require.True(t, inner.flushed)
}

func TestResponseRecorder_HijackDelegatesToInner(t *testing.T) {
	inner := &hijackerWriter{ResponseRecorder: httptest.NewRecorder()}
	rr := &responseRecorder{ResponseWriter: inner, status: 200}
	_, _, _ = rr.Hijack()
	require.True(t, inner.hijackCalled)
	require.True(t, rr.hijacked)
}

func TestResponseRecorder_HijackFallsBackIfNotSupported(t *testing.T) {
	rr := &responseRecorder{ResponseWriter: httptest.NewRecorder(), status: 200}
	_, _, err := rr.Hijack()
	require.ErrorIs(t, err, http.ErrNotSupported)
}

func TestResponseRecorder_UnwrapReturnsInner(t *testing.T) {
	inner := httptest.NewRecorder()
	rr := &responseRecorder{ResponseWriter: inner, status: 200}
	require.Equal(t, http.ResponseWriter(inner), rr.Unwrap())
}

func TestTraceHandler_ResolveHeaderName_InlineWins(t *testing.T) {
	h := &TraceHandler{HeaderName: "X-Custom-Trace"}
	require.Equal(t, "X-Custom-Trace", h.resolveHeaderName())
}

func TestTraceHandler_ResolveHeaderName_EnvFallback(t *testing.T) {
	t.Setenv("APX_TRACE_HEADER", "X-From-Env")
	h := &TraceHandler{}
	require.Equal(t, "X-From-Env", h.resolveHeaderName())
}

func TestTraceHandler_ValidToken_EmitsReceivedAndResponse(t *testing.T) {
	secret := "test-secret"
	app := newFakeTraceApp(secret)
	h := &TraceHandler{
		headerName: "X-APX-Debug-Trace",
		app:        app,
		redactor:   DefaultRedactor(),
	}
	tok := validTokenFor(t, secret, TokenPayload{DebugRequestID: "dr-xyz", VhostID: 99})

	r := httptest.NewRequest("GET", "/foo", nil)
	r.Header.Set("X-APX-Debug-Trace", tok)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextHandlerOK()))

	require.Equal(t, 3, app.eventCount(),
		"expected cluster_received + cluster_response_started + cluster_response")
	events := app.eventsCopy()
	require.Equal(t, EventClusterReceived, events[0].Type)
	require.Equal(t, EventClusterResponseStarted, events[1].Type)
	require.Equal(t, EventClusterResponse, events[2].Type)
	require.Equal(t, tok, app.tokens[0])
	require.Equal(t, tok, app.tokens[1])
	require.Equal(t, tok, app.tokens[2])
	// request_id should be consistent across all three.
	require.Equal(t, events[0].Payload["request_id"], events[1].Payload["request_id"])
	require.Equal(t, events[0].Payload["request_id"], events[2].Payload["request_id"])
	// cluster_response_started must be stamped at-or-before cluster_response
	// since the former fires on first Write and the latter in the deferred
	// finalizer after the handler returns.
	require.LessOrEqual(t, events[1].TsNs, events[2].TsNs)
}

// findEvent returns the first event of the given type, or fails the test.
func findEvent(t *testing.T, events []Event, typ string) Event {
	t.Helper()
	for _, e := range events {
		if e.Type == typ {
			return e
		}
	}
	t.Fatalf("expected event of type %q; got types %v", typ, eventTypes(events))
	return Event{}
}

func eventTypes(events []Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Type
	}
	return out
}

func TestResponseMutation_EmittedWhenResponseHeadersDiffer(t *testing.T) {
	secret := "s"
	app := newFakeTraceApp(secret)
	h := &TraceHandler{
		headerName: "X-APX-Debug-Trace",
		app:        app,
		redactor:   DefaultRedactor(),
	}
	tok := validTokenFor(t, secret, TokenPayload{DebugRequestID: "dr-1", VhostID: 1})

	r := httptest.NewRequest("GET", "/foo", nil)
	r.Header.Set("X-APX-Debug-Trace", tok)
	w := httptest.NewRecorder()

	// Simulate: outer handler runs, reverse_proxy transport captures upstream
	// headers into TraceContext, then a response-header mutator modifies them
	// before the response leaves Caddy.
	upstreamHeaders := http.Header{
		"Server":        {"nginx"},
		"Cache-Control": {"no-cache"},
	}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		tc := FromContext(r.Context())
		require.NotNil(t, tc, "trace context must be present in next handler")
		tc.UpstreamResponseHeaders = upstreamHeaders.Clone()

		// Final response: Server removed, Cache-Control changed, X-Frame-Options added.
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(200)
		return nil
	})

	require.NoError(t, h.ServeHTTP(w, r, next))

	events := app.eventsCopy()
	mut := findEvent(t, events, EventResponseMutation)
	require.Equal(t, SourceCluster, mut.Source)
	require.Equal(t, "response", mut.Payload["label"])
	require.NotEmpty(t, mut.Payload["request_id"])

	diff, ok := mut.Payload["diff"].(SnapshotDiff)
	require.True(t, ok, "diff should be a SnapshotDiff; got %T", mut.Payload["diff"])

	require.Len(t, diff.HeadersAdded, 1)
	require.Equal(t, "X-Frame-Options", diff.HeadersAdded[0].Name)
	require.Equal(t, []string{"DENY"}, diff.HeadersAdded[0].After)

	require.Len(t, diff.HeadersRemoved, 1)
	require.Equal(t, "Server", diff.HeadersRemoved[0].Name)
	require.Equal(t, []string{"nginx"}, diff.HeadersRemoved[0].Before)

	require.Len(t, diff.HeadersChanged, 1)
	require.Equal(t, "Cache-Control", diff.HeadersChanged[0].Name)
	require.Equal(t, []string{"no-cache"}, diff.HeadersChanged[0].Before)
	require.Equal(t, []string{"public, max-age=60"}, diff.HeadersChanged[0].After)

	// response_mutation must come before cluster_response.
	mutIdx := indexOfEvent(events, EventResponseMutation)
	respIdx := indexOfEvent(events, EventClusterResponse)
	require.Less(t, mutIdx, respIdx, "response_mutation must be emitted before cluster_response")
}

func TestResponseMutation_NotEmittedWhenNoChanges(t *testing.T) {
	secret := "s"
	app := newFakeTraceApp(secret)
	h := &TraceHandler{
		headerName: "X-APX-Debug-Trace",
		app:        app,
		redactor:   DefaultRedactor(),
	}
	tok := validTokenFor(t, secret, TokenPayload{DebugRequestID: "dr-1", VhostID: 1})

	r := httptest.NewRequest("GET", "/foo", nil)
	r.Header.Set("X-APX-Debug-Trace", tok)
	w := httptest.NewRecorder()

	upstream := http.Header{"Content-Type": {"text/plain"}}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		tc := FromContext(r.Context())
		tc.UpstreamResponseHeaders = upstream.Clone()
		// Final response mirrors upstream exactly.
		for k, vs := range upstream {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(200)
		return nil
	})

	require.NoError(t, h.ServeHTTP(w, r, next))

	for _, e := range app.eventsCopy() {
		require.NotEqual(t, EventResponseMutation, e.Type,
			"no response_mutation should be emitted when headers are unchanged")
	}
}

func TestResponseMutation_NotEmittedWhenNoUpstreamSnapshot(t *testing.T) {
	secret := "s"
	app := newFakeTraceApp(secret)
	h := &TraceHandler{
		headerName: "X-APX-Debug-Trace",
		app:        app,
		redactor:   DefaultRedactor(),
	}
	tok := validTokenFor(t, secret, TokenPayload{DebugRequestID: "dr-1", VhostID: 1})

	r := httptest.NewRequest("GET", "/foo", nil)
	r.Header.Set("X-APX-Debug-Trace", tok)
	w := httptest.NewRecorder()

	// Handler sets some response headers but never populates
	// UpstreamResponseHeaders — e.g. request short-circuited before any
	// upstream round-trip. Must not emit response_mutation.
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Handler-Set", "yep")
		w.WriteHeader(204)
		return nil
	})

	require.NoError(t, h.ServeHTTP(w, r, next))

	for _, e := range app.eventsCopy() {
		require.NotEqual(t, EventResponseMutation, e.Type,
			"no response_mutation should be emitted without upstream snapshot")
	}
}

func TestResponseMutation_RedactsSensitiveValues(t *testing.T) {
	secret := "s"
	app := newFakeTraceApp(secret)
	h := &TraceHandler{
		headerName: "X-APX-Debug-Trace",
		app:        app,
		redactor:   DefaultRedactor(),
	}
	tok := validTokenFor(t, secret, TokenPayload{DebugRequestID: "dr-1", VhostID: 1})

	r := httptest.NewRequest("GET", "/foo", nil)
	r.Header.Set("X-APX-Debug-Trace", tok)
	w := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		tc := FromContext(r.Context())
		tc.UpstreamResponseHeaders = http.Header{"Set-Cookie": {"session=upstream-secret"}}
		w.Header().Set("Set-Cookie", "session=rewritten-secret")
		w.WriteHeader(200)
		return nil
	})

	require.NoError(t, h.ServeHTTP(w, r, next))

	mut := findEvent(t, app.eventsCopy(), EventResponseMutation)
	diff := mut.Payload["diff"].(SnapshotDiff)
	require.Len(t, diff.HeadersChanged, 1)
	change := diff.HeadersChanged[0]
	require.Equal(t, "Set-Cookie", change.Name)
	require.Len(t, change.Before, 1)
	require.Len(t, change.After, 1)
	require.True(t, strings.HasPrefix(change.Before[0], "<sha256:"),
		"before value should be redacted, got %q", change.Before[0])
	require.True(t, strings.HasPrefix(change.After[0], "<sha256:"),
		"after value should be redacted, got %q", change.After[0])
	require.NotContains(t, change.Before[0], "upstream-secret")
	require.NotContains(t, change.After[0], "rewritten-secret")
}

func indexOfEvent(events []Event, typ string) int {
	for i, e := range events {
		if e.Type == typ {
			return i
		}
	}
	return -1
}
