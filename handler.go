package apxstats

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// StatsHandler is the HTTP middleware. Installed once at the top of the
// global handler chain so it sees every request the cluster serves.
type StatsHandler struct {
	logger *zap.Logger
	app    AppRef
}

// CaddyModule registers the handler at "http.handlers.apx_stats".
func (*StatsHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_stats",
		New: func() caddy.Module { return new(StatsHandler) },
	}
}

// Provision looks up the StatsApp and stashes a reference. Fails hard if
// the app isn't configured — running the handler without the app would
// silently drop counters, which is worse than a clear startup error.
func (h *StatsHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.app != nil {
		return nil
	}
	app, err := ctx.App("apx_stats")
	if err != nil {
		return fmt.Errorf("apx_stats handler requires apx_stats app: %w", err)
	}
	sa, ok := app.(*StatsApp)
	if !ok {
		return fmt.Errorf("apx_stats handler: unexpected app type %T", app)
	}
	h.app = sa
	return nil
}

// UnmarshalCaddyfile parses an empty block. The handler takes no config
// today — all knobs live on the app.
func (h *StatsHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

// ServeHTTP records one row's worth of stats per request. Hot path is
// designed to avoid allocations beyond the wrapper struct.
func (h *StatsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	start := time.Now()

	wrapped := &recorder{ResponseWriter: w, status: 200}
	servErr := next.ServeHTTP(wrapped, r)

	dur := time.Since(start)
	h.record(r, wrapped, dur)
	return servErr
}

// record reads context off the request after next.ServeHTTP returns.
// vhost_id, country, ASN, and the reverse-proxy outcome placeholders are
// all set by handlers earlier in the chain.
func (h *StatsHandler) record(r *http.Request, w *recorder, dur time.Duration) {
	vhostID, ok := readVhostID(r)
	if !ok {
		// No vhost_id set — request didn't match a vhost route. Skip;
		// recording a counter under vhost_id=0 would pollute aggregates.
		metricRequestsTotal.WithLabelValues("no_vhost").Inc()
		return
	}

	repl, _ := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	origin := classifyOrigin(repl, w.status)
	country := readCountry(repl)
	asn := readASN(repl)
	durationUs := uint64(dur.Microseconds())

	k := Key{
		TsUnixMin: uint32(time.Now().UTC().Unix() / 60),
		VhostID:   vhostID,
		Method:    methodOrUnknown(r.Method),
		Status:    uint16(w.status),
		Origin:    origin,
		Country:   country,
		ASN:       asn,
	}
	d := CounterDelta{
		BytesIn:    requestBytes(r),
		BytesOut:   uint64(w.bytes),
		DurationUs: durationUs,
		LatBucket:  BucketForUs(durationUs),
	}

	h.app.Record(k, d)
	metricRequestsTotal.WithLabelValues(origin).Inc()
}

// readVhostID reads `http.vars.vhost_id` set by the per-vhost vars
// handler in caddy_config_files.ex. Returns false if absent or
// unparseable; defensive — in production the var is always present.
func readVhostID(r *http.Request) (uint32, bool) {
	v := caddyhttp.GetVar(r.Context(), "vhost_id")
	if v == nil {
		return 0, false
	}
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// classifyOrigin maps a finished request to one of three origin classes.
//
//   - upstream: reverse_proxy attempted AND its upstream status equals
//     the final response status. Caddy passed the upstream response
//     through without rewriting it.
//   - cluster_proxy_error: reverse_proxy attempted but the final status
//     differs from the upstream status. Caddy synthesized the response
//     (timeout, connection refused, header rewrite, etc.).
//   - cluster: reverse_proxy was never reached. Caddy generated the
//     response itself (404 from no matching route, redirect, error
//     page, etc.).
//
// `{http.reverse_proxy.upstream.address}` and
// `{http.reverse_proxy.status_code}` are set by the stdlib reverse_proxy
// handler when it runs. The address placeholder is set to a string and
// the status_code placeholder is set to an int — we route both through
// Replacer.GetString so the comparison is uniform.
func classifyOrigin(repl *caddy.Replacer, finalStatus int) string {
	if repl == nil {
		return OriginCluster
	}
	upstream, ok := repl.GetString("http.reverse_proxy.upstream.address")
	if !ok || upstream == "" {
		return OriginCluster
	}
	upstreamStatus, ok := repl.GetString("http.reverse_proxy.status_code")
	if !ok || upstreamStatus == "" {
		// Reverse proxy was attempted but no status came back: connection
		// error, dial timeout, etc. Caddy is what the client saw.
		return OriginClusterProxyError
	}
	if upstreamStatus == strconv.Itoa(finalStatus) {
		return OriginUpstream
	}
	return OriginClusterProxyError
}

// readCountry returns the ISO 3166 alpha-2 country code from the
// caddy-geoip2 placeholder, or "" if unavailable. The plugin sets this
// only when configured (see proxy_server.country_headers in the app).
func readCountry(repl *caddy.Replacer) string {
	if repl == nil {
		return ""
	}
	s, _ := repl.GetString("geoip2.country_code")
	return normalizeCountry(s)
}

// readASN returns the ASN as uint32, or 0 if unavailable.
func readASN(repl *caddy.Replacer) uint32 {
	if repl == nil {
		return 0
	}
	s, ok := repl.GetString("geoip2.autonomous_system_number")
	if !ok || s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// normalizeCountry forces the country to a 2-byte uppercase ASCII code
// or "". Defensive: the placeholder usually returns clean values, but
// the lookup may return empty strings for private/loopback IPs.
func normalizeCountry(s string) string {
	if len(s) != 2 {
		return ""
	}
	out := []byte(s)
	for i, c := range out {
		if c >= 'a' && c <= 'z' {
			out[i] = c - ('a' - 'A')
		} else if c < 'A' || c > 'Z' {
			return ""
		}
	}
	return string(out)
}

// methodOrUnknown protects the cardinality of the method field. A
// malformed request can land an arbitrary token in r.Method; clamp to
// the standard verbs we'd expect to see in a reverse-proxy fleet.
func methodOrUnknown(m string) string {
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions,
		http.MethodConnect, http.MethodTrace:
		return m
	}
	return "OTHER"
}

// requestBytes estimates the request body size. We use Content-Length
// when set; chunked / unknown-length bodies report 0. Counting actual
// bytes off r.Body would require buffering the request stream, which
// adds cost and complexity disproportionate to the value of the metric.
func requestBytes(r *http.Request) uint64 {
	if r.ContentLength > 0 {
		return uint64(r.ContentLength)
	}
	return 0
}

// recorder captures status + bytes-out while still streaming to w. Same
// pattern as the trace handler's responseRecorder; kept private here to
// avoid coupling to that module.
type recorder struct {
	http.ResponseWriter
	status   int
	bytes    int
	wrote    bool
	hijacked bool
}

func (r *recorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.wrote = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController and Caddy reach the inner writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Flush delegates if supported; required for SSE / streaming responses.
func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates if supported; required for WebSocket upgrades.
//
// NOTE: once hijacked we lose visibility into bytes-out — the handler
// records what we have at the time of takeover (likely 0 for the
// upgrade response). That's acceptable for v1; raw-TCP traffic counters
// would need a different approach (transport-level counting).
func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		r.wrote = true
		r.hijacked = true
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Push delegates if supported (HTTP/2 server push).
func (r *recorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := r.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

var (
	_ caddy.Provisioner           = (*StatsHandler)(nil)
	_ caddyfile.Unmarshaler       = (*StatsHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*StatsHandler)(nil)
)
