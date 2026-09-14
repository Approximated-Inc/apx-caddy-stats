package apxstats

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"syscall"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// Caddy's DialError embeds an unexported error without Unwrap. The final
// handler error cannot expose the net.OpError through errors.As in that case.
type opaqueDialFailure struct{ error }

func failureWireRow(t *testing.T, modeV2 bool, selected bool, next caddyhttp.Handler) (map[string]any, error) {
	t.Helper()
	app := &fakeApp{modeV2: modeV2}
	h := &StatsHandler{app: app}
	var entries map[string]any
	if selected {
		entries = upstreamSelected("origin.example:443")
	}
	r := newRequestWithReplacer("GET", "https://customer.example/", "100", entries)
	err := h.ServeHTTP(httptest.NewRecorder(), r, next)
	rows := app.reqEventSnapshot()
	require.Len(t, rows, 1)
	if modeV2 {
		buffer := newRequestEventRecorderV2(10, 10, nil)
		buffer.record(rows[0])
		rows, _ = buffer.drain()
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	require.NoError(t, encodeRequestEventRow(gz, 42, rows[0]))
	require.NoError(t, gz.Close())
	zr, zerr := gzip.NewReader(&buf)
	require.NoError(t, zerr)
	defer zr.Close()
	var row map[string]any
	require.NoError(t, json.NewDecoder(zr).Decode(&row))
	return row, err
}

func TestUpstreamFailureReasons(t *testing.T) {
	dnsTimeout := &net.DNSError{Name: "origin.example", Err: "i/o timeout", IsTimeout: true}
	dnsMissing := &net.DNSError{Name: "origin.example", Err: "no such host", IsNotFound: true}
	connectTimeout := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	cert := x509.UnknownAuthorityError{}
	tests := []struct {
		name, want string
		err        error
		stage      string
	}{
		{"TCP timeout", "connect_timeout", connectTimeout, "connect"},
		{"TCP refused", "connection_refused", refused, "connect"},
		{"DNS timeout", "dns_timeout", dnsTimeout, "dns"},
		{"DNS missing", "dns_error", dnsMissing, "dns"},
		{"certificate", "tls_certificate_error", cert, "tls"},
		{"TLS timeout", "tls_handshake_timeout", context.DeadlineExceeded, "tls"},
		{"TLS alert", "tls_handshake_error", errors.New("remote error: tls: handshake failure"), "tls"},
		{"write timeout", "request_write_timeout", context.DeadlineExceeded, "write"},
		{"write error", "request_write_error", io.ErrClosedPipe, "write"},
		{"header timeout", "response_header_timeout", errors.New("net/http: timeout awaiting response headers"), ""},
		{"reset", "connection_reset", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, ""},
		{"EOF", "upstream_eof", io.EOF, ""},
		{"unexpected EOF", "upstream_eof", io.ErrUnexpectedEOF, ""},
		{"unclassified", "unknown", errors.New("unrecognized transport failure"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			terminal := tt.err
			if tt.stage == "connect" || tt.stage == "dns" {
				terminal = opaqueDialFailure{fmt.Errorf("dial tcp: %w", tt.err)}
			}
			handlerErr := caddyhttp.Error(502, terminal)
			row, gotErr := failureWireRow(t, true, true, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				trace := httptrace.ContextClientTrace(r.Context())
				if trace != nil {
					switch tt.stage {
					case "connect":
						trace.ConnectDone("tcp", "192.0.2.1:443", tt.err)
					case "dns":
						trace.DNSDone(httptrace.DNSDoneInfo{Err: tt.err})
					case "tls":
						trace.TLSHandshakeDone(tls.ConnectionState{}, tt.err)
					case "write":
						trace.WroteRequest(httptrace.WroteRequestInfo{Err: tt.err})
					}
				}
				return handlerErr
			}))
			require.Equal(t, handlerErr, gotErr, "must preserve the proxy error")
			require.Equal(t, tt.want, row["upstream_failure_reason"])
			require.Equal(t, "cluster_proxy_error", row["origin"])
			require.Equal(t, "served", row["disposition"], "failure classification must not change sampling")
			require.Equal(t, float64(502), row["status"])
		})
	}
}

func TestUpstreamFailureDoesNotLeakFailedAttempt(t *testing.T) {
	for _, status := range []int{200, 502} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			row, err := failureWireRow(t, true, true, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				if tr := httptrace.ContextClientTrace(r.Context()); tr != nil {
					tr.ConnectDone("tcp", "192.0.2.1:443", context.DeadlineExceeded)
				}
				w.WriteHeader(103)
				w.WriteHeader(status)
				return nil
			}))
			require.NoError(t, err)
			require.Empty(t, row["upstream_failure_reason"])
			require.Equal(t, float64(status), row["status"])
			require.Equal(t, "upstream", row["origin"])
		})
	}
}

func TestUpstreamFailureIgnoresUnrelatedLateDialError(t *testing.T) {
	row, _ := failureWireRow(t, true, true, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if tr := httptrace.ContextClientTrace(r.Context()); tr != nil {
			tr.ConnectDone("tcp", "192.0.2.1:443", context.DeadlineExceeded)
		}
		return caddyhttp.Error(502, io.EOF)
	}))
	require.Equal(t, "upstream_eof", row["upstream_failure_reason"])
}

func TestUpstreamFailureExcludesCancellationAndNonProxyErrors(t *testing.T) {
	for _, selected := range []bool{true, false} {
		for _, status := range []int{499, 502} {
			row, _ := failureWireRow(t, true, selected, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return caddyhttp.Error(status, context.Canceled)
			}))
			require.Empty(t, row["upstream_failure_reason"])
		}
	}
	row, _ := failureWireRow(t, true, false, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(502, errors.New("local handler failure"))
	}))
	require.Empty(t, row["upstream_failure_reason"])
}

func TestUpstreamFailureNoAvailableUpstreams(t *testing.T) {
	row, _ := failureWireRow(t, true, false, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(503, errors.New("no upstreams available"))
	}))
	require.Equal(t, "cluster_proxy_error", row["origin"])
	require.Equal(t, "no_upstreams_available", row["upstream_failure_reason"])
}

func TestUpstreamFailureLegacyDoesNotInstallHooks(t *testing.T) {
	row, _ := failureWireRow(t, false, true, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		require.Nil(t, httptrace.ContextClientTrace(r.Context()))
		return caddyhttp.Error(502, io.EOF)
	}))
	_, present := row["upstream_failure_reason"]
	require.False(t, present)
}

func TestUpstreamFailurePreservesCaddyRequestIdentity(t *testing.T) {
	w := httptest.NewRecorder()
	repl := caddy.NewReplacer()
	r := caddyhttp.PrepareRequest(httptest.NewRequest("GET", "https://customer.example/", nil), repl, w, &caddyhttp.Server{})
	caddyhttp.SetVar(r.Context(), "vhost_id", "100")
	h := &StatsHandler{app: &fakeApp{modeV2: true}}
	require.NoError(t, h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, changed *http.Request) error {
		changed.Method = "POST"
		changed.Host = "rewritten.example"
		method, _ := repl.GetString("http.request.method")
		host, _ := repl.GetString("http.request.host")
		require.Equal(t, "POST", method)
		require.Equal(t, "rewritten.example", host)
		return nil
	})))
}

func TestUpstreamFailureKeepsFirstAddressError(t *testing.T) {
	first := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, Err: syscall.ECONNREFUSED}
	last := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 443}, Err: context.DeadlineExceeded}
	row, _ := failureWireRow(t, true, true, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		trace := httptrace.ContextClientTrace(r.Context())
		trace.ConnectDone("tcp", "192.0.2.1:443", first)
		trace.ConnectDone("tcp", "192.0.2.2:443", last)
		return caddyhttp.Error(502, opaqueDialFailure{first})
	}))
	require.Equal(t, "connection_refused", row["upstream_failure_reason"])
}

func BenchmarkUpstreamFailureTrace(b *testing.B) {
	r := httptest.NewRequest("GET", "https://customer.example/", nil)
	ctx := r.Context()
	b.ReportAllocs()
	for b.Loop() {
		_, trace := withUpstreamFailureTrace(r)
		trace.close()
		*r = *r.WithContext(ctx)
	}
}
