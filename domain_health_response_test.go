package apxstats

import (
	"context"
	"encoding/json"
	"io"
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

// Run the pinned Caddy reverse_proxy itself, including its swallowed-cancel
// and response-retry paths. The transport is deterministic and opens no sockets.
func TestDomainHealthCaddyResponseEvidence(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		rewrite      string
		replace      bool
		cancel       bool
		earlyHints   bool
		retry        bool
		cancelRetry  bool
		cancelParent bool
		failed       bool
		preexisting  bool
		cancelAfter  bool
		want         domainHealthCounter
		wantError    bool
	}{
		{name: "actual 204", status: 204, want: domainHealthCounter{1, 1, 1, 1, 0, 0}},
		{name: "actual redirect", status: 302, want: domainHealthCounter{1, 1, 1, 1, 0, 0}},
		{name: "actual auth response", status: 401, want: domainHealthCounter{1, 1, 1, 0, 0, 0}},
		{name: "actual upstream 503", status: 503, want: domainHealthCounter{1, 1, 1, 0, 1, 0}},
		{name: "actual response updates stale latency", status: 200, preexisting: true, want: domainHealthCounter{1, 1, 1, 1, 0, 0}},
		{name: "503 rewritten to 200", status: 503, rewrite: "200", want: domainHealthCounter{1, 1, 1, 0, 1, 0}},
		{name: "200 rewritten to 503", status: 200, rewrite: "503", want: domainHealthCounter{1, 1, 1, 1, 0, 0}},
		{name: "503 replaced by response route", status: 503, replace: true, want: domainHealthCounter{1, 1, 1, 0, 1, 0}},
		{name: "client cancel after written 200", status: 200, cancelAfter: true, want: domainHealthCounter{1, 1, 1, 1, 0, 0}},
		{name: "client cancel after written 503", status: 503, cancelAfter: true, want: domainHealthCounter{1, 1, 1, 0, 1, 0}},
		{name: "cancel before any response nil return", cancel: true, cancelParent: true, want: domainHealthCounter{RequestCount: 1}},
		{name: "transport cancellation with live parent", cancel: true, want: domainHealthCounter{RequestCount: 1}},
		{name: "early hints then cancellation", earlyHints: true, cancel: true, want: domainHealthCounter{RequestCount: 1}},
		{name: "stale 200 retry then cancellation", status: 200, retry: true, cancelRetry: true, want: domainHealthCounter{RequestCount: 1}},
		{name: "stale 503 retry then cancellation", status: 503, retry: true, cancelRetry: true, cancelParent: true, want: domainHealthCounter{RequestCount: 1}},
		{name: "final response retry error", status: 503, retry: true, wantError: true, want: domainHealthCounter{1, 1, 1, 0, 1, 0}},
		{name: "failed transport", failed: true, wantError: true, want: domainHealthCounter{RequestCount: 1, ProxyErrors: 1}},
		{name: "stale 200 retry then transport failure", status: 200, retry: true, failed: true, wantError: true, want: domainHealthCounter{RequestCount: 1, ProxyErrors: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			proxy := domainHealthProxy(t, failureRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if tc.failed && (!tc.retry || calls > 1) {
					return nil, io.EOF
				}
				if tc.cancel || tc.cancelRetry && calls > 1 {
					if tc.earlyHints {
						require.NoError(t, httptrace.ContextClientTrace(r.Context()).Got1xxResponse(103, nil))
					}
					if tc.cancelParent {
						cancel()
					}
					return nil, context.Canceled
				}
				body := "origin"
				if tc.status == http.StatusNoContent {
					body = ""
				}
				return &http.Response{StatusCode: tc.status, Status: http.StatusText(tc.status), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			}), func(proxy *reverseproxy.Handler) {
				if tc.rewrite != "" {
					proxy.HandleResponse = []caddyhttp.ResponseHandler{{StatusCode: caddyhttp.WeakString(tc.rewrite)}}
				}
				if tc.replace {
					proxy.HandleResponse = []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{{HandlersRaw: []json.RawMessage{json.RawMessage(`{"handler":"static_response","status_code":200,"body":"replacement"}`)}}}}}
				}
				if tc.retry {
					proxy.LoadBalancing = &reverseproxy.LoadBalancing{Retries: 1, RetryMatchRaw: caddyhttp.RawMatcherSets{{"expression": json.RawMessage(`"{http.reverse_proxy.status_code} >= 200"`)}}}
				}
			})
			app := &fakeDomainHealthApp{}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "http://customer.example/", nil).WithContext(parent)
			// PrepareRequest binds all Caddy context to the cancellable request.
			r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, &caddyhttp.Server{})
			caddyhttp.SetVar(r.Context(), "vhost_id", "12")
			caddyhttp.SetVar(r.Context(), domainHealthVar, strings.Repeat("a", 64))
			if tc.preexisting {
				setDomainHealthUpstreamResponse(r, 200)
			}
			err := (&StatsHandler{app: app}).ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				err := proxy.ServeHTTP(w, r, nextHandler(404))
				if tc.cancelAfter {
					cancel()
				}
				return err
			}))
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "Caddy deliberately swallows context.Canceled")
			}
			if tc.retry {
				require.Equal(t, 2, calls)
			}
			require.Len(t, app.health, 1)
			require.Equal(t, tc.want, app.health[0].counter)
			assertDomainHealthVector(t, app.health[0].counter)
		})
	}
}

func TestDomainHealthRejectsUnprovenResponsePlaceholders(t *testing.T) {
	for _, preexisting := range []bool{false, true} {
		t.Run(map[bool]string{false: "selected address and recorder 200", true: "stale response placeholders"}[preexisting], func(t *testing.T) {
			app := &fakeDomainHealthApp{}
			r := newRequestWithReplacer("GET", "https://site.example/", "12", upstreamSelected("origin:443"))
			caddyhttp.SetVar(r.Context(), domainHealthVar, strings.Repeat("a", 64))
			if preexisting {
				setDomainHealthUpstreamResponse(r, 200)
			}
			require.NoError(t, (&StatsHandler{app: app}).ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
				w.WriteHeader(200)
				return nil
			})))
			require.Len(t, app.health, 1)
			require.Equal(t, domainHealthCounter{RequestCount: 1, RoutingResponses: 1}, app.health[0].counter)
			assertDomainHealthVector(t, app.health[0].counter)
		})
	}
}

func TestDomainHealthCaddyHijackRetainsOriginal101(t *testing.T) {
	for _, cancelAfter := range []bool{false, true} {
		t.Run(map[bool]string{false: "open", true: "client cancel after upgrade"}[cancelAfter], func(t *testing.T) {
			testDomainHealthCaddyHijack(t, cancelAfter)
		})
	}
}

func testDomainHealthCaddyHijack(t *testing.T, cancelAfter bool) {
	app := &fakeDomainHealthApp{}
	stats := &StatsHandler{app: app}
	proxy := caddyProxy(t, upgradeEchoUpstream(t))
	done := make(chan error, 1)
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		r = caddyhttp.PrepareRequest(r.WithContext(ctx), caddy.NewReplacer(), w, &caddyhttp.Server{})
		caddyhttp.SetVar(r.Context(), "vhost_id", "12")
		caddyhttp.SetVar(r.Context(), domainHealthVar, strings.Repeat("a", 64))
		done <- stats.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			err := proxy.ServeHTTP(w, r, nextHandler(404))
			if cancelAfter {
				cancel() // the client resets the upgraded stream
			}
			return err
		}))
	}))
	t.Cleanup(edge.Close)
	exchangeWebSocketFrames(t, edge.Listener.Addr().String(), "/socket")
	waitHandled(t, done)
	require.Len(t, app.health, 1)
	require.Equal(t, domainHealthCounter{RequestCount: 1, RoutingResponses: 1, UpstreamResponses: 1}, app.health[0].counter, "101 proves reachability without becoming a 2xx success")
	assertDomainHealthVector(t, app.health[0].counter)
}

func domainHealthProxy(t *testing.T, transport http.RoundTripper, configure func(*reverseproxy.Handler)) *reverseproxy.Handler {
	t.Helper()
	ctx, err := caddy.ProvisionContext(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}})
	require.NoError(t, err)
	ctx, cancel := caddy.NewContext(ctx)
	t.Cleanup(cancel)
	proxy := &reverseproxy.Handler{Transport: transport, Upstreams: reverseproxy.UpstreamPool{&reverseproxy.Upstream{Dial: "192.0.2.1:443"}}}
	configure(proxy)
	require.NoError(t, proxy.Provision(ctx))
	t.Cleanup(func() { require.NoError(t, proxy.Cleanup()) })
	return proxy
}

func assertDomainHealthVector(t *testing.T, c domainHealthCounter) {
	t.Helper()
	require.LessOrEqual(t, c.UpstreamSuccesses+c.Upstream5xx, c.UpstreamResponses)
	require.LessOrEqual(t, c.UpstreamResponses, c.RoutingResponses)
	require.LessOrEqual(t, c.RoutingResponses+c.ProxyErrors, c.RequestCount)
}
