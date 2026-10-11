package apxstats

import (
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
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/stretchr/testify/require"
)

// maskedCause is how coraza-caddy (managed_header_privacy) hands back a
// masked request's transport error it cannot classify: same HandlerError,
// cause text withheld.
func maskedCause(status int) error { return caddyhttp.Error(status, errors.New("")) }

// The connector's empty-text outer wrapper around a HandlerError.
type emptyOuterError struct{ cause error }

func (emptyOuterError) Error() string   { return "" }
func (e emptyOuterError) Unwrap() error { return e.cause }

// Dial-stage failures of a masked request classify from this request's
// httptrace evidence, exactly as the unmasked request does.
func TestUpstreamFailureReasonForPrivacyMaskedCause(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	for _, tc := range []struct {
		name, want string
		status     int
		trace      func(*httptrace.ClientTrace)
	}{
		{"connection_refused", "connection_refused", 502, func(tr *httptrace.ClientTrace) { tr.ConnectDone("tcp", "127.0.0.1:1", refused) }},
		{"connection_refused_both_families", "connection_refused", 502, func(tr *httptrace.ClientTrace) {
			tr.ConnectDone("tcp", "[::1]:1", &net.OpError{Op: "dial", Net: "tcp6", Err: syscall.ECONNREFUSED})
			tr.ConnectDone("tcp", "127.0.0.1:1", refused)
		}},
		{"connect_timeout", "connect_timeout", 502, func(tr *httptrace.ClientTrace) { tr.ConnectDone("tcp", "192.0.2.1:81", timeout) }},
		{"dns_error", "dns_error", 502, func(tr *httptrace.ClientTrace) {
			tr.DNSDone(httptrace.DNSDoneInfo{Err: &net.DNSError{Name: "origin.invalid", Err: "no such host", IsNotFound: true}})
		}},
		{"dns_timeout", "dns_timeout", 502, func(tr *httptrace.ClientTrace) {
			tr.DNSDone(httptrace.DNSDoneInfo{Err: &net.DNSError{Name: "origin.invalid", Err: "i/o timeout", IsTimeout: true}})
		}},
		{"tls_handshake_error", "tls_handshake_error", 502, func(tr *httptrace.ClientTrace) {
			tr.TLSHandshakeDone(tls.ConnectionState{}, errors.New("tls: first record does not look like a TLS handshake"))
		}},
		{"tls_handshake_timeout", "tls_handshake_timeout", 504, func(tr *httptrace.ClientTrace) {
			tr.TLSHandshakeDone(tls.ConnectionState{}, context.DeadlineExceeded)
		}},
		{"ambiguous_stages", "unknown", 502, func(tr *httptrace.ClientTrace) {
			tr.ConnectDone("tcp", "127.0.0.1:1", refused)
			tr.ConnectDone("tcp", "192.0.2.1:81", timeout)
		}},
		{"no_evidence", "unknown", 502, func(*httptrace.ClientTrace) {}},
		// A connection that succeeded after a dial failure (a retry to another
		// upstream, or the other address family) means the dial failure did
		// not end the request.
		{"refused_then_connected", "unknown", 502, func(tr *httptrace.ClientTrace) {
			tr.ConnectDone("tcp", "127.0.0.1:1", refused)
			tr.ConnectDone("tcp", "127.0.0.1:2", nil)
		}},
		{"refused_then_reused_connection", "unknown", 502, func(tr *httptrace.ClientTrace) {
			tr.ConnectDone("tcp", "127.0.0.1:1", refused)
			tr.GotConn(httptrace.GotConnInfo{Reused: true})
		}},
		{"other_family_refused_then_connected", "unknown", 502, func(tr *httptrace.ClientTrace) {
			tr.ConnectDone("tcp", "[::1]:1", &net.OpError{Op: "dial", Net: "tcp6", Err: syscall.ECONNREFUSED})
			tr.ConnectDone("tcp", "127.0.0.1:1", nil)
			tr.GotConn(httptrace.GotConnInfo{})
		}},
		{"connected_then_refused", "connection_refused", 502, func(tr *httptrace.ClientTrace) {
			tr.ConnectDone("tcp", "127.0.0.1:2", nil)
			tr.GotConn(httptrace.GotConnInfo{})
			tr.ConnectDone("tcp", "127.0.0.1:1", refused)
		}},
		{"refused_connected_refused_again", "connection_refused", 502, func(tr *httptrace.ClientTrace) {
			tr.ConnectDone("tcp", "127.0.0.1:1", refused)
			tr.ConnectDone("tcp", "127.0.0.1:2", nil)
			tr.ConnectDone("tcp", "127.0.0.1:1", refused)
		}},
		{"connected_then_tls_failed", "tls_handshake_error", 502, func(tr *httptrace.ClientTrace) {
			tr.ConnectDone("tcp", "127.0.0.1:1", refused)
			tr.ConnectDone("tcp", "127.0.0.1:2", nil)
			tr.TLSHandshakeDone(tls.ConnectionState{}, errors.New("tls: first record does not look like a TLS handshake"))
		}},
	} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapped=%v", tc.name, wrapped), func(t *testing.T) {
				row, _ := failureWireRow(t, true, true, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					tc.trace(httptrace.ContextClientTrace(r.Context()))
					if wrapped {
						return emptyOuterError{maskedCause(tc.status)}
					}
					return maskedCause(tc.status)
				}))
				require.Equal(t, tc.want, row["upstream_failure_reason"])
			})
		}
	}
	// A non-empty cause that matches no evidence keeps its old classification.
	row, _ := failureWireRow(t, true, true, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		httptrace.ContextClientTrace(r.Context()).ConnectDone("tcp", "127.0.0.1:1", refused)
		return caddyhttp.Error(502, errors.New("unrelated transport failure"))
	}))
	require.Equal(t, "unknown", row["upstream_failure_reason"])
}

// connectorSafeCause reproduces coraza-caddy's privateCause/safeErrorClass
// (codex/header-privacy-connector @ 7b6e353) for a masked request.
func connectorSafeCause(err error) error {
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var dns *net.DNSError
	var op *net.OpError
	switch {
	case err.Error() == "no upstreams available" && errors.Unwrap(err) == nil:
		return err
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case retriedUpstreamResponse(caddyhttp.HandlerError{Err: err}):
		return err
	case errors.As(err, &verification) || errors.As(err, &authority) || errors.As(err, &invalid) || errors.As(err, &hostname):
		return &tls.CertificateVerificationError{Err: errors.New("certificate verification failed")}
	case errors.As(err, &dns):
		return &net.DNSError{Err: "lookup failed", IsTimeout: dns.Timeout()}
	case errors.Is(err, syscall.ECONNRESET):
		return syscall.ECONNRESET
	case errors.Is(err, io.ErrUnexpectedEOF):
		return io.ErrUnexpectedEOF
	case errors.Is(err, io.EOF):
		return io.EOF
	case err.Error() == "net/http: timeout awaiting response headers":
		return errors.New("net/http: timeout awaiting response headers")
	case errors.As(err, &op) && op.Op == "write":
		cause := error(syscall.EPIPE)
		if op.Timeout() {
			cause = os.ErrDeadlineExceeded
		}
		return &net.OpError{Op: "write", Net: "tcp", Err: cause}
	}
	return errors.New("")
}

func emulatedMaskingConnector(next caddyhttp.Handler) caddyhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		err := next.ServeHTTP(w, r)
		var he caddyhttp.HandlerError
		if err == nil || !errors.As(err, &he) {
			return err
		}
		if he.Err != nil {
			he.Err = connectorSafeCause(he.Err)
		}
		return he
	}
}

// A real Caddy reverse_proxy behind a connector that masks its errors records
// the same upstream_failure_reason as without masking, for every failure kind.
func TestUpstreamFailureRealCaddyProxyMaskedMatchesUnmasked(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}})
	require.NoError(t, err)
	ctx, cancel := caddy.NewContext(ctx)
	t.Cleanup(cancel)
	listen := func(handle func(net.Conn)) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go handle(c)
			}
		}()
		return ln.Addr().String()
	}
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "origin body") }))
	t.Cleanup(ok.Close)
	okAddress := strings.TrimPrefix(ok.URL, "http://")
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(slow.Close)
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(tlsServer.Close)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddress := closed.Addr().String()
	require.NoError(t, closed.Close())
	eof := listen(func(c net.Conn) { buf := make([]byte, 4096); _, _ = c.Read(buf); _ = c.Close() })
	reset := listen(func(c net.Conn) {
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_ = c.(*net.TCPConn).SetLinger(0)
		_ = c.Close()
	})
	silent := listen(func(c net.Conn) { time.Sleep(2 * time.Second); _ = c.Close() })

	for _, tt := range []struct {
		name, address, want string
		transport           func(*reverseproxy.HTTPTransport)
	}{
		{"refused", closedAddress, "connection_refused", nil},
		{"dns_error", "nonexistent-upstream.invalid:80", "dns_error", func(tr *reverseproxy.HTTPTransport) {
			tr.Resolver = &reverseproxy.UpstreamResolver{Addresses: []string{"127.0.0.1:9"}}
		}},
		{"tls_handshake_error", okAddress, "tls_handshake_error", func(tr *reverseproxy.HTTPTransport) {
			tr.TLS = &reverseproxy.TLSConfig{InsecureSkipVerify: true}
		}},
		{"tls_handshake_timeout", silent, "tls_handshake_timeout", func(tr *reverseproxy.HTTPTransport) {
			tr.TLS = &reverseproxy.TLSConfig{InsecureSkipVerify: true, HandshakeTimeout: caddy.Duration(100 * time.Millisecond)}
		}},
		{"tls_certificate_error", strings.TrimPrefix(tlsServer.URL, "https://"), "tls_certificate_error", func(tr *reverseproxy.HTTPTransport) {
			tr.TLS = &reverseproxy.TLSConfig{}
		}},
		{"response_header_timeout", strings.TrimPrefix(slow.URL, "http://"), "response_header_timeout", nil},
		{"upstream_eof", eof, "upstream_eof", nil},
		{"connection_reset", reset, "reset_or_eof", nil},
		{"no_upstreams", "", "no_upstreams_available", nil},
		{"success", okAddress, "", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			run := func(masked bool) string {
				transport := &reverseproxy.HTTPTransport{ResponseHeaderTimeout: caddy.Duration(100 * time.Millisecond), DialTimeout: caddy.Duration(300 * time.Millisecond)}
				if tt.transport != nil {
					tt.transport(transport)
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
				var inner caddyhttp.Handler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return proxy.ServeHTTP(w, r, nextHandler(404)) })
				if masked {
					inner = emulatedMaskingConnector(inner)
				}
				app := &fakeApp{modeV2: true}
				completed := make(chan struct{})
				downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(completed)
					r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, &caddyhttp.Server{})
					caddyhttp.SetVar(r.Context(), "vhost_id", "100")
					if err := (&StatsHandler{app: app}).ServeHTTP(w, r, inner); err != nil {
						var he caddyhttp.HandlerError
						require.True(t, errors.As(err, &he))
						w.WriteHeader(he.StatusCode)
					}
				}))
				defer downstream.Close()
				response, err := (&http.Client{Timeout: 5 * time.Second}).Get(downstream.URL + "/")
				require.NoError(t, err)
				_, _ = io.ReadAll(response.Body)
				require.NoError(t, response.Body.Close())
				<-completed
				rows := app.reqEventSnapshot()
				require.Len(t, rows, 1)
				return rows[0].UpstreamFailureReason
			}
			unmasked, masked := run(false), run(true)
			if tt.want == "reset_or_eof" {
				// A reset races the read of the closed connection; both are typed causes.
				require.Contains(t, []string{"connection_reset", "upstream_eof"}, unmasked)
				require.Contains(t, []string{"connection_reset", "upstream_eof"}, masked)
				return
			}
			require.Equal(t, tt.want, unmasked, "fixture no longer produces the expected unmasked reason")
			require.Equal(t, unmasked, masked, "masking changed upstream_failure_reason")
		})
	}
}

// A masked request whose final error is not a stage failure must not take its
// reason from a dial failure that a later successful connection superseded:
// a load-balancer retry to another upstream, or the other address family of
// one hostname. Real Caddy reverse_proxy, masked == unmasked == unknown.
func TestUpstreamFailureRealCaddyProxyMaskedIgnoresSupersededDialFailures(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}})
	require.NoError(t, err)
	ctx, cancel := caddy.NewContext(ctx)
	t.Cleanup(cancel)
	malformedListener := func(network, address string) *net.TCPAddr {
		ln, err := net.Listen(network, address)
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					buf := make([]byte, 4096)
					_, _ = c.Read(buf)
					_, _ = io.WriteString(c, "garbage-not-http\r\n\r\n")
					_ = c.Close()
				}(c)
			}
		}()
		return ln.Addr().(*net.TCPAddr)
	}
	closedAddress := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		address := ln.Addr().String()
		require.NoError(t, ln.Close())
		return address
	}
	run := func(config string, masked bool) string {
		proxy := new(reverseproxy.Handler)
		require.NoError(t, json.Unmarshal([]byte(config), proxy))
		require.NoError(t, proxy.Provision(ctx))
		t.Cleanup(func() { require.NoError(t, proxy.Cleanup()) })
		var inner caddyhttp.Handler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return proxy.ServeHTTP(w, r, nextHandler(404)) })
		if masked {
			inner = emulatedMaskingConnector(inner)
		}
		app := &fakeApp{modeV2: true}
		completed := make(chan struct{})
		downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(completed)
			r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, &caddyhttp.Server{})
			caddyhttp.SetVar(r.Context(), "vhost_id", "100")
			if err := (&StatsHandler{app: app}).ServeHTTP(w, r, inner); err != nil {
				var he caddyhttp.HandlerError
				require.True(t, errors.As(err, &he))
				w.WriteHeader(he.StatusCode)
			}
		}))
		defer downstream.Close()
		response, err := (&http.Client{Timeout: 10 * time.Second}).Get(downstream.URL + "/")
		require.NoError(t, err)
		_, _ = io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
		<-completed
		rows := app.reqEventSnapshot()
		require.Len(t, rows, 1)
		return rows[0].UpstreamFailureReason
	}
	t.Run("lb_retry_after_refused_upstream", func(t *testing.T) {
		config := func() string {
			// Fresh upstream addresses per run: passive health state is shared by address.
			return fmt.Sprintf(`{"transport":{"protocol":"http","dial_timeout":"300ms"},"upstreams":[{"dial":%q},{"dial":%q}],"load_balancing":{"selection_policy":{"policy":"first"},"retries":3},"health_checks":{"passive":{"fail_duration":"30s","max_fails":1}}}`,
				closedAddress(), malformedListener("tcp", "127.0.0.1:0").String())
		}
		unmasked, masked := run(config(), false), run(config(), true)
		require.Equal(t, "unknown", unmasked, "fixture no longer produces the expected unmasked reason")
		require.Equal(t, unmasked, masked, "masking changed upstream_failure_reason")
	})
	t.Run("dual_stack_ipv6_refused_ipv4_connected", func(t *testing.T) {
		addrs, err := net.LookupHost("localhost")
		require.NoError(t, err)
		if len(addrs) < 2 || net.ParseIP(addrs[0]).To4() != nil {
			t.Skip("localhost does not resolve to ::1 before 127.0.0.1 here")
		}
		port := malformedListener("tcp4", "127.0.0.1:0").Port
		config := fmt.Sprintf(`{"transport":{"protocol":"http","dial_timeout":"300ms"},"upstreams":[{"dial":"localhost:%d"}]}`, port)
		unmasked, masked := run(config, false), run(config, true)
		require.Equal(t, "unknown", unmasked, "fixture no longer produces the expected unmasked reason")
		require.Equal(t, unmasked, masked, "masking changed upstream_failure_reason")
	})
}
