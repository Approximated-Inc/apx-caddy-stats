package apxstats

import (
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(LatencyRecorder{})
}

// LatencyRecorder wraps the reverse_proxy handler and folds the upstream
// round-trip Caddy has already measured into the latency registry. It adds
// no measurement of its own: Caddy sets both replacer variables during
// normal proxying whether or not anything reads them.
//
// Deliberately a separate module from the apx_stats handler: that handler
// is only emitted for clusters with stats enabled, and latency selection
// must not silently depend on stats being on.
type LatencyRecorder struct{}

// CaddyModule returns the Caddy module information.
func (LatencyRecorder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_lb_recorder",
		New: func() caddy.Module { return new(LatencyRecorder) },
	}
}

// ServeHTTP runs the rest of the chain, then records what the proxy did.
func (LatencyRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	err := next.ServeHTTP(w, r)

	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return err
	}

	// upstream.latency is set only after a response came back, so its
	// presence is the signal that this upstream actually served. Dial
	// failures never set it, which matters: recording one would make a
	// fast failure look like the fastest upstream.
	raw, ok := repl.Get("http.reverse_proxy.upstream.latency")
	if !ok {
		return err
	}
	d, ok := raw.(time.Duration)
	if !ok {
		return err
	}

	// hostport is dialInfo.Address, which matches Upstream.Dial — the key
	// the selector looks up. (The stats handler reads upstream.address for
	// its own purposes; that one is dialInfo.String() and is not the same
	// string.) On a retry the replacer holds the last upstream tried, which
	// is the one that actually served.
	hostport, ok := repl.GetString("http.reverse_proxy.upstream.hostport")
	if !ok || hostport == "" {
		return err
	}

	lbRecord(hostport, d)
	return err
}

var _ caddyhttp.MiddlewareHandler = (*LatencyRecorder)(nil)
