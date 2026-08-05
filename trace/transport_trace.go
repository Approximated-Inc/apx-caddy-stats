package apxtrace

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// TraceTransport wraps an inner reverse_proxy transport. Delegates RoundTrip
// and emits upstream_request / upstream_response / upstream_error events
// only when a trace context is present.
type TraceTransport struct {
	InnerRaw json.RawMessage `json:"inner,omitempty" caddy:"namespace=http.reverse_proxy.transport inline_key=protocol"`

	inner    http.RoundTripper
	redactor *Redactor
	app      AppRef
}

// CaddyModule registers the transport.
func (*TraceTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.apx_trace",
		New: func() caddy.Module { return new(TraceTransport) },
	}
}

// Provision loads the inner transport module and looks up the TraceApp.
func (t *TraceTransport) Provision(ctx caddy.Context) error {
	t.redactor = DefaultRedactor()
	if len(t.InnerRaw) == 0 {
		// Default inner = http
		t.InnerRaw = []byte(`{"protocol":"http"}`)
	}
	val, err := ctx.LoadModule(t, "InnerRaw")
	if err != nil {
		return fmt.Errorf("apx_trace transport: load inner: %w", err)
	}
	rt, ok := val.(http.RoundTripper)
	if !ok {
		return fmt.Errorf("apx_trace transport: inner is not RoundTripper: %T", val)
	}
	t.inner = rt

	if t.app == nil {
		app, err := ctx.App("apx_trace")
		if err != nil {
			return fmt.Errorf("apx_trace transport requires apx_trace app to be configured: %w", err)
		}
		ta, ok := app.(*TraceApp)
		if !ok {
			return fmt.Errorf("apx_trace transport: unexpected app type %T", app)
		}
		t.app = ta
	}
	return nil
}

// Cleanup delegates to inner if it implements CleanerUpper.
func (t *TraceTransport) Cleanup() error {
	if c, ok := t.inner.(caddy.CleanerUpper); ok {
		return c.Cleanup()
	}
	return nil
}

// RoundTrip delegates to the inner transport, emitting trace events when a
// TraceContext is present on the request.
func (t *TraceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tc := FromContext(r.Context())
	if tc == nil {
		return t.inner.RoundTrip(r)
	}

	redactor := t.redactor
	if redactor == nil {
		redactor = DefaultRedactor()
	}

	upstream := fmt.Sprintf("%s://%s", r.URL.Scheme, r.URL.Host)
	tc.App.EmitEvent(Event{
		Type:   EventUpstreamRequest,
		TsNs:   time.Now().UnixNano(),
		Source: SourceCluster,
		Payload: map[string]any{
			"upstream":   upstream,
			"method":     r.Method,
			"uri":        r.URL.RequestURI(),
			"headers":    redactor.RedactHeaders(r.Header),
			"request_id": tc.RequestID,
		},
	}, tc.Token)

	start := time.Now()
	resp, err := t.inner.RoundTrip(r)
	duration := time.Since(start)

	if err != nil {
		tc.App.EmitEvent(Event{
			Type:   EventUpstreamError,
			TsNs:   time.Now().UnixNano(),
			Source: SourceCluster,
			Payload: map[string]any{
				"upstream":       upstream,
				"error":          err.Error(),
				"classification": classifyUpstreamError(err),
				"duration_ms":    duration.Milliseconds(),
				"request_id":     tc.RequestID,
			},
		}, tc.Token)
		return resp, err
	}

	// Snapshot response headers BEFORE any Caddy-side response mutations so the
	// outer handler can diff them against the final wrapped response headers.
	if resp != nil {
		cloned := make(http.Header, len(resp.Header))
		for k, vs := range resp.Header {
			cp := make([]string, len(vs))
			copy(cp, vs)
			cloned[k] = cp
		}
		tc.UpstreamResponseHeaders = cloned
	}

	tc.App.EmitEvent(Event{
		Type:   EventUpstreamResponse,
		TsNs:   time.Now().UnixNano(),
		Source: SourceCluster,
		Payload: map[string]any{
			"upstream":    upstream,
			"status":      resp.StatusCode,
			"headers":     redactor.RedactHeaders(resp.Header),
			"duration_ms": duration.Milliseconds(),
			"request_id":  tc.RequestID,
		},
	}, tc.Token)
	return resp, nil
}

func classifyUpstreamError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "refused"):
		return "dial"
	case strings.Contains(msg, "tls"), strings.Contains(msg, "x509"):
		return "tls"
	default:
		return "other"
	}
}

var (
	_ caddy.Provisioner  = (*TraceTransport)(nil)
	_ caddy.CleanerUpper = (*TraceTransport)(nil)
	_ http.RoundTripper  = (*TraceTransport)(nil)
)
