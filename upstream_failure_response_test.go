package apxstats

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/stretchr/testify/require"
)

type failureRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f failureRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpstreamFailureAfterResponse(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}})
	require.NoError(t, err)
	ctx, cancel := caddy.NewContext(ctx)
	t.Cleanup(cancel)
	for _, tt := range []struct {
		name, origin, reason string
		retry, finalDial     bool
	}{
		{"exhausted response retries", "upstream", "", true, false},
		{"local response handler", "cluster", "", false, false},
		{"response then failed dial", "cluster_proxy_error", "connect_timeout", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			proxy := &reverseproxy.Handler{
				Upstreams: reverseproxy.UpstreamPool{&reverseproxy.Upstream{Dial: "192.0.2.1:443"}},
				Transport: failureRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if tt.finalDial && calls > 1 {
						err := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
						httptrace.ContextClientTrace(r.Context()).ConnectDone("tcp", "192.0.2.1:443", err)
						return nil, opaqueDialFailure{err}
					}
					return &http.Response{StatusCode: 502, Status: "502 Bad Gateway", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("origin error")), Request: r}, nil
				}),
			}
			if tt.retry {
				proxy.LoadBalancing = &reverseproxy.LoadBalancing{Retries: 1, RetryMatchRaw: caddyhttp.RawMatcherSets{{"expression": json.RawMessage(`"{http.reverse_proxy.status_code} == 502"`)}}}
			} else {
				proxy.HandleResponse = []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{{HandlersRaw: []json.RawMessage{json.RawMessage(`{"handler":"error","status_code":502,"error":"local response handler failure"}`)}}}}}
			}
			require.NoError(t, proxy.Provision(ctx))
			t.Cleanup(func() { require.NoError(t, proxy.Cleanup()) })
			app := &fakeApp{modeV2: true}
			stats := &StatsHandler{app: app}
			w := httptest.NewRecorder()
			r := caddyhttp.PrepareRequest(httptest.NewRequest("GET", "http://customer.example/", nil), caddy.NewReplacer(), w, &caddyhttp.Server{})
			caddyhttp.SetVar(r.Context(), "vhost_id", "100")
			err := stats.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return proxy.ServeHTTP(w, r, nextHandler(404)) }))
			require.Error(t, err)
			rows := app.reqEventSnapshot()
			require.Len(t, rows, 1)
			require.Equal(t, uint16(502), rows[0].Status)
			require.Equal(t, tt.origin, rows[0].Origin)
			require.Equal(t, tt.reason, rows[0].UpstreamFailureReason)
			if tt.retry {
				require.Equal(t, 2, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}
