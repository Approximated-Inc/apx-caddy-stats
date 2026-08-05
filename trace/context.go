package apxtrace

import (
	"context"
	"net/http"
	"time"
)

type ctxKey struct{}

// TraceContext travels on the request context for the duration of a traced
// request. Only present when a valid trace token was verified by HMAC.
//
// Not safe for concurrent mutation across goroutines: the trace pipeline
// assumes a single-threaded handler chain per request.
type TraceContext struct {
	Token          string
	DebugRequestID string
	VhostID        int64
	RequestID      string
	StartTime      time.Time
	App            AppRef
	LastSnapshot   RequestSnapshot

	// UpstreamResponseHeaders is a snapshot of response headers captured inside
	// the reverse_proxy transport at the moment the upstream returned, BEFORE
	// any Caddy-side response mutations are applied. Nil when no upstream
	// round-trip occurred (e.g. handler short-circuit, upstream error).
	UpstreamResponseHeaders http.Header
}

func withTrace(ctx context.Context, tc *TraceContext) context.Context {
	return context.WithValue(ctx, ctxKey{}, tc)
}

// FromContext returns the active TraceContext if present, else nil.
func FromContext(ctx context.Context) *TraceContext {
	tc, _ := ctx.Value(ctxKey{}).(*TraceContext)
	return tc
}
