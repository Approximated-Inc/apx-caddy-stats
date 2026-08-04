package apxtrace

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

func newTraceContextFor(t *testing.T, token string, app AppRef) *TraceContext {
	t.Helper()
	return &TraceContext{
		Token:          token,
		DebugRequestID: "dr-1",
		VhostID:        42,
		RequestID:      "req1",
		StartTime:      time.Now(),
		App:            app,
		LastSnapshot:   RequestSnapshot{Method: "GET", URI: "/foo", Headers: http.Header{}},
	}
}

func TestMarkHandler_NoTrace_IsNoop(t *testing.T) {
	app := newFakeTraceApp("s")
	h := &MarkHandler{Phase: "enter", Label: "edge_sequence", app: app}
	r := httptest.NewRequest("GET", "/foo", nil)
	w := httptest.NewRecorder()
	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	require.NoError(t, h.ServeHTTP(w, r, next))
	require.True(t, called)
	require.Equal(t, 0, app.eventCount())
}

func TestMarkHandler_EnterPhase_EmitsEdgeSequenceEntered(t *testing.T) {
	app := newFakeTraceApp("s")
	tc := newTraceContextFor(t, "tok", app)
	h := &MarkHandler{
		Phase:    "enter",
		Label:    "edge_sequence",
		Metadata: map[string]string{"edge_sequence_id": "42"},
		app:      app,
	}
	r := httptest.NewRequest("GET", "/foo", nil)
	r = r.WithContext(withTrace(r.Context(), tc))
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })))

	require.Equal(t, 1, app.eventCount())
	events := app.eventsCopy()
	require.Equal(t, EventEdgeSequenceEntered, events[0].Type)
}

func TestMarkHandler_EnterPhase_DefaultLabelEmitsRouteMatched(t *testing.T) {
	app := newFakeTraceApp("s")
	tc := newTraceContextFor(t, "tok", app)
	h := &MarkHandler{Phase: "enter", Label: "route", app: app}
	r := httptest.NewRequest("GET", "/foo", nil)
	r = r.WithContext(withTrace(r.Context(), tc))
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })))

	events := app.eventsCopy()
	require.Len(t, events, 1)
	require.Equal(t, EventRouteMatched, events[0].Type)
}

func TestMarkHandler_PostPhase_EmitsMutationWithDiff(t *testing.T) {
	app := newFakeTraceApp("s")
	tc := newTraceContextFor(t, "tok", app)
	h := &MarkHandler{
		Phase:    "post",
		Label:    "edge_rule",
		Metadata: map[string]string{"edge_rule_id": "117"},
		app:      app,
	}
	r := httptest.NewRequest("GET", "/foo", nil)
	r.Header.Set("X-Added", "1")
	r = r.WithContext(withTrace(r.Context(), tc))
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })))

	require.Equal(t, 1, app.eventCount())
	events := app.eventsCopy()
	require.Equal(t, EventRequestMutation, events[0].Type)
}
