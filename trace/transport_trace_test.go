package apxtrace

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubRT struct {
	resp *http.Response
	err  error
}

func (s *stubRT) RoundTrip(*http.Request) (*http.Response, error) { return s.resp, s.err }

func TestTraceTransport_NoActiveTrace_DelegatesCleanly(t *testing.T) {
	tt := &TraceTransport{inner: &stubRT{resp: &http.Response{StatusCode: 200, Header: http.Header{}}}}
	r := httptest.NewRequest("GET", "http://up.local/foo", nil)
	resp, err := tt.RoundTrip(r)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
}

func TestTraceTransport_ActiveTrace_EmitsRequestAndResponse(t *testing.T) {
	app := newFakeTraceApp("s")
	tc := newTraceContextFor(t, "tok", app)
	tt := &TraceTransport{
		inner:    &stubRT{resp: &http.Response{StatusCode: 502, Header: http.Header{"Server": {"nginx"}}}},
		redactor: DefaultRedactor(),
		app:      app,
	}

	r := httptest.NewRequest("GET", "http://up.local/foo", nil)
	r = r.WithContext(withTrace(r.Context(), tc))

	_, err := tt.RoundTrip(r)
	require.NoError(t, err)

	require.Equal(t, 2, app.eventCount())
	events := app.eventsCopy()
	require.Equal(t, EventUpstreamRequest, events[0].Type)
	require.Equal(t, EventUpstreamResponse, events[1].Type)
}

func TestTraceTransport_ActiveTrace_CapturesUpstreamResponseHeaders(t *testing.T) {
	app := newFakeTraceApp("s")
	tc := newTraceContextFor(t, "tok", app)
	upstreamHeaders := http.Header{
		"Server":        {"nginx"},
		"Cache-Control": {"public, max-age=60"},
	}
	tt := &TraceTransport{
		inner:    &stubRT{resp: &http.Response{StatusCode: 200, Header: upstreamHeaders}},
		redactor: DefaultRedactor(),
		app:      app,
	}

	r := httptest.NewRequest("GET", "http://up.local/foo", nil)
	r = r.WithContext(withTrace(r.Context(), tc))

	_, err := tt.RoundTrip(r)
	require.NoError(t, err)

	require.NotNil(t, tc.UpstreamResponseHeaders)
	require.Equal(t, []string{"nginx"}, tc.UpstreamResponseHeaders["Server"])
	require.Equal(t, []string{"public, max-age=60"}, tc.UpstreamResponseHeaders["Cache-Control"])

	// Mutating the upstream response header map after RoundTrip must not
	// bleed into the captured snapshot.
	upstreamHeaders.Set("Server", "something-else")
	require.Equal(t, []string{"nginx"}, tc.UpstreamResponseHeaders["Server"],
		"snapshot should be independent of upstream header map")
}

func TestTraceTransport_Error_DoesNotSetUpstreamResponseHeaders(t *testing.T) {
	app := newFakeTraceApp("s")
	tc := newTraceContextFor(t, "tok", app)
	tt := &TraceTransport{
		inner:    &stubRT{err: errors.New("dial tcp: refused")},
		redactor: DefaultRedactor(),
		app:      app,
	}

	r := httptest.NewRequest("GET", "http://up.local/foo", nil)
	r = r.WithContext(withTrace(r.Context(), tc))

	_, err := tt.RoundTrip(r)
	require.Error(t, err)
	require.Nil(t, tc.UpstreamResponseHeaders, "no upstream headers should be captured on error")
}

func TestTraceTransport_Error_EmitsUpstreamError(t *testing.T) {
	app := newFakeTraceApp("s")
	tc := newTraceContextFor(t, "tok", app)
	tt := &TraceTransport{
		inner:    &stubRT{err: errors.New("dial tcp: timeout")},
		redactor: DefaultRedactor(),
		app:      app,
	}

	r := httptest.NewRequest("GET", "http://up.local/foo", nil)
	r = r.WithContext(withTrace(r.Context(), tc))

	_, err := tt.RoundTrip(r)
	require.Error(t, err)

	require.Equal(t, 2, app.eventCount())
	events := app.eventsCopy()
	require.Equal(t, EventUpstreamRequest, events[0].Type)
	require.Equal(t, EventUpstreamError, events[1].Type)
}
