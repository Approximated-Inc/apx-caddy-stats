package apxstats

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"reflect"
	"strings"
	"sync"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type upstreamFailureContextKey struct{}

// Evidence is bounded and request-local. Nothing from error text is shipped.
// HTTP trace callbacks can run concurrently, even after ServeHTTP returns.
type upstreamFailureTrace struct {
	mu       sync.Mutex
	closed   bool
	evidence []upstreamFailureEvidence
}

type upstreamFailureEvidence struct{ message, reason string }

func withUpstreamFailureTrace(r *http.Request) (*http.Request, *upstreamFailureTrace) {
	f := new(upstreamFailureTrace)
	trace := &httptrace.ClientTrace{
		DNSDone: func(i httptrace.DNSDoneInfo) {
			if i.Err == nil {
				return
			}
			reason := "dns_error"
			if timeoutError(i.Err) {
				reason = "dns_timeout"
			}
			f.record(i.Err, reason)
		},
		ConnectDone: func(network, _ string, err error) {
			if err == nil {
				return
			}
			// Only TCP connections have the advertised connect-timeout meaning.
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return
			}
			reason := "unknown"
			if timeoutError(err) {
				reason = "connect_timeout"
			} else if errors.Is(err, syscall.ECONNREFUSED) {
				reason = "connection_refused"
			}
			f.record(err, reason)
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				return
			}
			reason := "tls_handshake_error"
			if certificateError(err) {
				reason = "tls_certificate_error"
			} else if timeoutError(err) {
				reason = "tls_handshake_timeout"
			}
			f.record(err, reason)
		},
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			if i.Err == nil {
				return
			}
			reason := "request_write_error"
			if timeoutError(i.Err) {
				reason = "request_write_timeout"
			}
			f.record(i.Err, reason)
		},
	}
	ctx := context.WithValue(r.Context(), upstreamFailureContextKey{}, f)
	// PrepareRequest binds Caddy's replacer to this exact request pointer.
	// Preserve it so later Host/method rewrites also update placeholders.
	*r = *r.WithContext(httptrace.WithClientTrace(ctx, trace))
	return r, f
}

func (f *upstreamFailureTrace) record(err error, reason string) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	message := err.Error()
	// Overlong errors are deliberately unclassified; never retain arbitrary
	// request-controlled strings in the tracking state.
	if len(message) == 0 || len(message) > 512 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	for _, prior := range f.evidence {
		if prior.message == message && prior.reason == reason {
			return
		}
	}
	// A hostname may dial several addresses concurrently. net.Dialer can
	// return an earlier address's error rather than the last callback's.
	// Allocate only on failure and retain a bounded set across attempts.
	if len(f.evidence) < 16 {
		f.evidence = append(f.evidence, upstreamFailureEvidence{message, reason})
	}
}

func (f *upstreamFailureTrace) close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}

func (f *upstreamFailureTrace) reason(err error) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	message := err.Error()
	reason := ""
	for _, evidence := range f.evidence {
		// Caddy's DialError has no Unwrap method. Match the actual final
		// error against stage evidence, including the net.OpError prefix,
		// instead of letting a failed earlier attempt determine the result.
		if evidence.message == "" || !(message == evidence.message || strings.HasSuffix(message, ": "+evidence.message)) {
			continue
		}
		if reason != "" && reason != evidence.reason {
			return "unknown"
		}
		reason = evidence.reason
	}
	return reason
}

func timeoutError(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func certificateError(err error) bool {
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verification *tls.CertificateVerificationError
	return errors.As(err, &authority) || errors.As(err, &invalid) || errors.As(err, &hostname) || errors.As(err, &verification)
}

// Caddy 2.11.3's no-upstream sentinel is unexported. Match the exact leaf
// error and status (not substrings or durations). There is no selected
// upstream placeholder on this path.
func noAvailableUpstreams(err error) bool {
	if err == nil {
		return false
	}
	var he caddyhttp.HandlerError
	return errors.As(err, &he) && he.StatusCode == 503 && he.Err != nil && he.Err.Error() == "no upstreams available"
}

// Caddy does not export this response-retry type or an interface for it.
// Inspect its exact package/type identity instead of treating its HTTP 5xx
// as a failed transport or matching user-controlled error text. The pinned
// Caddy integration test guards this compatibility boundary.
func retriedUpstreamResponse(err error) bool {
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) {
		return false
	}
	for inner := he.Err; inner != nil; inner = errors.Unwrap(inner) {
		typ := reflect.TypeOf(inner)
		if typ.PkgPath() == "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy" && typ.Name() == "retryableResponseError" {
			return true
		}
	}
	return false
}

func localResponseHandlerError(repl *caddy.Replacer, err error) bool {
	if repl == nil {
		return false
	}
	if _, responded := repl.Get("http.reverse_proxy.upstream.latency"); !responded {
		return false
	}
	var he caddyhttp.HandlerError
	// A built-in response handler's HandlerError retains its original trace;
	// transport errors get their HandlerError in reverseproxy.statusError.
	// Do not infer success from latency alone: it survives later failed retries.
	return errors.As(err, &he) && he.Trace != "" && !strings.HasPrefix(he.Trace, "reverseproxy.statusError ")
}

func upstreamFailureReason(r *http.Request, w *recorder, err error, origin string) string {
	if err == nil {
		return ""
	}
	status := finalStatus(w, err)
	if origin != OriginClusterProxyError || status < 500 || status > 599 || w.wrote || r.Context().Err() != nil || errors.Is(err, context.Canceled) {
		return ""
	}
	var he caddyhttp.HandlerError
	if noAvailableUpstreams(err) {
		return "no_upstreams_available"
	}
	if errors.As(err, &he) && he.Err != nil {
		err = he.Err
	}
	if certificateError(err) {
		return "tls_certificate_error"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.Timeout() {
			return "dns_timeout"
		}
		return "dns_error"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "connection_reset"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "upstream_eof"
	}
	// net/http exposes no sentinel for its response-header deadline.
	if err.Error() == "net/http: timeout awaiting response headers" {
		return "response_header_timeout"
	}
	if f, ok := r.Context().Value(upstreamFailureContextKey{}).(*upstreamFailureTrace); ok {
		if reason := f.reason(err); reason != "" {
			return reason
		}
	}
	// Small requests may remain buffered until after WroteRequest(nil).
	// A failure in the subsequent flush still carries the typed write error.
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "write" {
		if timeoutError(op) {
			return "request_write_timeout"
		}
		return "request_write_error"
	}
	return "unknown"
}
