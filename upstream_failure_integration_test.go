package apxstats

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/stretchr/testify/require"
)

func TestUpstreamFailureRealCaddyProxy(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}})
	require.NoError(t, err)
	ctx, cancel := caddy.NewContext(ctx)
	t.Cleanup(cancel)

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(103)
		if r.URL.Path == "/origin-error" {
			w.WriteHeader(502)
		}
		_, _ = io.WriteString(w, "origin body")
	}))
	t.Cleanup(ok.Close)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(slow.Close)
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(tlsServer.Close)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddress := closed.Addr().String()
	require.NoError(t, closed.Close())

	for _, tt := range []struct {
		name, address, path, reason string
		tls                         bool
		status                      int
	}{
		{"success", strings.TrimPrefix(ok.URL, "http://"), "/", "", false, 200},
		{"origin 502", strings.TrimPrefix(ok.URL, "http://"), "/origin-error", "", false, 502},
		{"refused", closedAddress, "/", "connection_refused", false, 502},
		{"header timeout", strings.TrimPrefix(slow.URL, "http://"), "/", "response_header_timeout", false, 504},
		{"TLS certificate", strings.TrimPrefix(tlsServer.URL, "https://"), "/", "tls_certificate_error", true, 502},
		{"no upstream", "", "/", "no_upstreams_available", false, 503},
	} {
		t.Run(tt.name, func(t *testing.T) {
			transport := &reverseproxy.HTTPTransport{ResponseHeaderTimeout: caddy.Duration(50 * time.Millisecond)}
			if tt.tls {
				transport.TLS = &reverseproxy.TLSConfig{}
			}
			require.NoError(t, transport.Provision(ctx))
			transport.Transport.Proxy = nil
			t.Cleanup(func() { require.NoError(t, transport.Cleanup()) })
			proxy := &reverseproxy.Handler{Transport: transport}
			if tt.address != "" {
				proxy.Upstreams = reverseproxy.UpstreamPool{&reverseproxy.Upstream{Dial: tt.address}}
			}
			require.NoError(t, proxy.Provision(ctx))
			t.Cleanup(func() { require.NoError(t, proxy.Cleanup()) })
			app := &fakeApp{modeV2: true}
			stats := &StatsHandler{app: app}
			completed := make(chan error, 1)
			downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, &caddyhttp.Server{})
				caddyhttp.SetVar(r.Context(), "vhost_id", "100")
				err := stats.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return proxy.ServeHTTP(w, r, nextHandler(404))
				}))
				if err != nil {
					http.Error(w, "proxy failure", err.(caddyhttp.HandlerError).StatusCode)
				}
				completed <- err
			}))
			t.Cleanup(downstream.Close)
			client := &http.Client{Timeout: time.Second}
			response, err := client.Get(downstream.URL + tt.path)
			require.NoError(t, err)
			body, readErr := io.ReadAll(response.Body)
			require.NoError(t, response.Body.Close())
			require.NoError(t, readErr)
			require.Equal(t, tt.status, response.StatusCode)
			err = <-completed
			if tt.reason == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			rows := app.reqEventSnapshot()
			require.Len(t, rows, 1)
			require.Equal(t, uint16(tt.status), rows[0].Status)
			require.Equal(t, tt.reason, rows[0].UpstreamFailureReason)
			if tt.reason == "" {
				require.Equal(t, "origin body", string(body))
			}
		})
	}
}

func TestUpstreamFailureTraceConcurrentAndAfterReturn(t *testing.T) {
	var trace *httptrace.ClientTrace
	row, _ := failureWireRow(t, true, true, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		trace = httptrace.ContextClientTrace(r.Context())
		require.NotNil(t, trace)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); trace.ConnectDone("tcp", "192.0.2.1:443", context.DeadlineExceeded) }()
		}
		wg.Wait()
		return caddyhttp.Error(502, context.DeadlineExceeded)
	}))
	require.Equal(t, "connect_timeout", row["upstream_failure_reason"])
	// net/http permits late callbacks. They must not mutate finalized state.
	trace.DNSDone(httptrace.DNSDoneInfo{Err: &net.DNSError{Err: "late failure"}})
}

func TestUpstreamFailureMemoryAccountingAndSampling(t *testing.T) {
	row := requestEventRow{V2: true, Disposition: "served", Origin: "cluster_proxy_error", Status: 502, UpstreamFailureReason: "connect_timeout"}
	without := row
	without.UpstreamFailureReason = ""
	require.Equal(t, len("connect_timeout"), requestEventRowBytes(&row)-requestEventRowBytes(&without))
	buffer := newRequestEventRecorderV2(100, 1, nil)
	for range 10 {
		buffer.record(row)
	}
	rows, _ := buffer.drain()
	require.Len(t, rows, 10, "upstream failures must keep served-row sampling")
	for _, got := range rows {
		require.Equal(t, uint16(1), got.SampleRate)
		require.Equal(t, "connect_timeout", got.UpstreamFailureReason)
	}
}
