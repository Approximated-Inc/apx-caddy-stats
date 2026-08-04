package apxtrace

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TraceHandler is the outer wrapper installed once per server.
// Dormant unless the configured trace header is present with a valid,
// HMAC-signed token.
type TraceHandler struct {
	HeaderName string `json:"header_name,omitempty"`

	logger     *zap.Logger
	headerName string
	app        AppRef
	redactor   *Redactor
}

// CaddyModule returns the Caddy module information.
func (*TraceHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_trace",
		New: func() caddy.Module { return new(TraceHandler) },
	}
}

// Provision looks up the TraceApp (registered at root ID "apx_trace") and
// stashes a reference. Fails if the app is not configured.
func (h *TraceHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	h.headerName = h.resolveHeaderName()
	h.redactor = DefaultRedactor()

	if h.app == nil {
		app, err := ctx.App("apx_trace")
		if err != nil {
			return fmt.Errorf("apx_trace handler requires apx_trace app to be configured: %w", err)
		}
		ta, ok := app.(*TraceApp)
		if !ok {
			return fmt.Errorf("apx_trace handler: unexpected app type %T", app)
		}
		h.app = ta
	}
	return nil
}

func (h *TraceHandler) resolveHeaderName() string {
	if h.HeaderName != "" {
		return h.HeaderName
	}
	return defaultStringEnv("APX_TRACE_HEADER", "X-APX-Debug-Trace")
}

// UnmarshalCaddyfile parses an empty block.
func (h *TraceHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

// ServeHTTP is the hot path. Must be cheap when no trace header is present.
func (h *TraceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	token := r.Header.Get(h.headerName)
	if token == "" {
		metricRequestsTotal.WithLabelValues("no_header").Inc()
		return next.ServeHTTP(w, r)
	}

	payload, err := ValidateToken(token, h.app.Secret())
	if err != nil {
		metricRequestsTotal.WithLabelValues("invalid_token").Inc()
		return next.ServeHTTP(w, r)
	}

	metricRequestsTotal.WithLabelValues("active").Inc()

	tc := &TraceContext{
		Token:          token,
		DebugRequestID: payload.DebugRequestID,
		VhostID:        payload.VhostID,
		RequestID:      uuid.NewString(),
		StartTime:      time.Now(),
		App:            h.app,
		LastSnapshot:   Snapshot(r),
	}

	h.app.EmitEvent(Event{
		Type:   EventClusterReceived,
		TsNs:   time.Now().UnixNano(),
		Source: SourceCluster,
		Payload: map[string]any{
			"method":     r.Method,
			"uri":        r.URL.RequestURI(),
			"host":       r.Host,
			"headers":    h.redactor.RedactHeaders(r.Header),
			"remote_ip":  r.RemoteAddr,
			"request_id": tc.RequestID,
		},
	}, token)

	wrapped := &responseRecorder{ResponseWriter: w, status: 200}
	// Emit cluster_response_started the first time anything tries to write
	// the response — before the body streams through flow control. Gives
	// the app a stable anchor for "last-leg" network timing that doesn't
	// depend on how long the body takes to drain.
	wrapped.onFirstWrite = func() {
		h.app.EmitEvent(Event{
			Type:   EventClusterResponseStarted,
			TsNs:   time.Now().UnixNano(),
			Source: SourceCluster,
			Payload: map[string]any{
				"request_id": tc.RequestID,
			},
		}, token)
	}
	req := r.WithContext(withTrace(r.Context(), tc))

	var servErr error
	defer func() {
		total := time.Since(tc.StartTime)
		p := map[string]any{
			"total_duration_ns": total.Nanoseconds(),
			"request_id":        tc.RequestID,
		}
		if wrapped.hijacked {
			p["hijacked"] = true
		} else {
			p["status"] = wrapped.status
			p["response_headers"] = h.redactor.RedactHeaders(wrapped.Header())
			p["bytes_written"] = wrapped.bytes
		}
		if servErr != nil {
			p["error"] = servErr.Error()
		}
		rec := recover()
		if rec != nil {
			p["panic"] = fmt.Sprintf("%v", rec)
		}

		// Emit response_mutation (once, cluster-wide) if the upstream returned
		// headers and Caddy's response-side middleware chain changed them.
		// Must come BEFORE cluster_response so timeline ordering stays
		// upstream_response → response_mutation → cluster_response.
		if tc.UpstreamResponseHeaders != nil && !wrapped.hijacked {
			diff := DiffHeadersOnly(tc.UpstreamResponseHeaders, wrapped.Header(), h.redactor)
			if !diff.Empty() {
				h.app.EmitEvent(Event{
					Type:   EventResponseMutation,
					TsNs:   time.Now().UnixNano(),
					Source: SourceCluster,
					Payload: map[string]any{
						"label":      "response",
						"diff":       diff,
						"request_id": tc.RequestID,
					},
				}, token)
			}
		}

		h.app.EmitEvent(Event{
			Type:    EventClusterResponse,
			TsNs:    time.Now().UnixNano(),
			Source:  SourceCluster,
			Payload: p,
		}, token)

		// Re-panic so Caddy's server-level recovery can handle it as usual.
		if rec != nil {
			panic(rec)
		}
	}()

	servErr = next.ServeHTTP(wrapped, req)
	return servErr
}

// responseRecorder captures status + bytes + headers while still writing to w.
type responseRecorder struct {
	http.ResponseWriter
	status       int
	bytes        int
	wrote        bool
	hijacked     bool
	onFirstWrite func() // called at most once on first WriteHeader/Write/Flush
}

// markWrote flips the wrote flag and fires onFirstWrite exactly once.
// Call this from every response-producing method (WriteHeader, Write,
// Flush) so the first one observed triggers the stamp, no matter which
// entry point the downstream handler uses.
func (rr *responseRecorder) markWrote() {
	if rr.wrote {
		return
	}
	rr.wrote = true
	if rr.onFirstWrite != nil {
		rr.onFirstWrite()
	}
}

func (rr *responseRecorder) WriteHeader(code int) {
	if rr.wrote {
		return
	}
	rr.status = code
	rr.markWrote()
	rr.ResponseWriter.WriteHeader(code)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	rr.markWrote()
	n, err := rr.ResponseWriter.Write(b)
	rr.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController (Go 1.20+) and Caddy traverse the
// wrapper chain so inner capabilities stay reachable.
func (rr *responseRecorder) Unwrap() http.ResponseWriter { return rr.ResponseWriter }

// Flush delegates to the inner writer if it implements http.Flusher.
// Required for SSE and any streaming response.
func (rr *responseRecorder) Flush() {
	if f, ok := rr.ResponseWriter.(http.Flusher); ok {
		rr.markWrote()
		f.Flush()
	}
}

// Hijack delegates to the inner writer if it implements http.Hijacker.
// Required for WebSocket upgrades and any raw TCP takeover.
func (rr *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rr.ResponseWriter.(http.Hijacker); ok {
		rr.wrote = true
		rr.hijacked = true
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Push delegates to the inner writer if it implements http.Pusher.
func (rr *responseRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := rr.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func defaultStringEnv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

var (
	_ caddy.Provisioner           = (*TraceHandler)(nil)
	_ caddyfile.Unmarshaler       = (*TraceHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*TraceHandler)(nil)
)
