package apxstats

import (
	"bufio"
	"errors"
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
//
// Approximated's own URL monitor probes carry an `apx-monitor` request
// header. We don't record those — they're our health-check traffic and
// would inflate every customer's request_count + skew the status mix
// (a healthy vhost monitor is mostly 200s; an unhealthy one is mostly
// 5xxs from us, not the customer's real users). Skip before any
// wrapping work.
func (h *StatsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Header.Get("apx-monitor") != "" {
		metricRequestsTotal.WithLabelValues("skipped_monitor").Inc()
		return next.ServeHTTP(w, r)
	}

	start := time.Now()

	wrapped := &recorder{ResponseWriter: w, status: 200}
	servErr := next.ServeHTTP(wrapped, r)

	dur := time.Since(start)
	h.record(r, wrapped, dur, servErr)
	return servErr
}

// record reads context off the request after next.ServeHTTP returns.
// vhost_id, country, and ASN come from placeholders set by handlers
// earlier in the chain. Origin uses servErr (the bubbled handler error)
// to detect reverse_proxy failures — see classifyOrigin.
func (h *StatsHandler) record(r *http.Request, w *recorder, dur time.Duration, servErr error) {
	vhostID, ok := readVhostID(r)
	if !ok {
		// No vhost_id set — request didn't match a vhost route. Skip;
		// recording a counter under vhost_id=0 would pollute aggregates.
		metricRequestsTotal.WithLabelValues("no_vhost").Inc()
		return
	}

	repl, _ := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	origin := classifyOrigin(repl, servErr)
	country := readCountry(repl)
	asn := readASN(repl)
	durationUs := uint64(dur.Microseconds())

	k := Key{
		TsUnixMin: uint32(time.Now().UTC().Unix() / 60),
		VhostID:   vhostID,
		Method:    methodOrUnknown(r.Method),
		Status:    finalStatus(w, servErr),
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
//   - upstream: reverse_proxy attempted and the upstream returned. Caddy
//     passed the response through to the client.
//   - cluster_proxy_error: reverse_proxy attempted but failed (dial
//     refused, timeout, no upstream selected, etc.). Caddy synthesized
//     the response (typically 502 / 504 / 503 / 499).
//   - cluster: reverse_proxy was never reached. Caddy generated the
//     response itself (404 from no matching route, redirect, WAF block,
//     rate limit, error page, etc.).
//
// Signal sources:
//
//   - `{http.reverse_proxy.upstream.address}` — set by reverse_proxy
//     during upstream *selection*, before the dial attempt. Set even
//     on dial failure. Absent ⇒ reverse_proxy never ran.
//   - servErr — the error returned by next.ServeHTTP. When reverse_proxy
//     fails, it returns a caddyhttp.HandlerError (502 by default, 504
//     for timeouts, 499 for client cancel) which bubbles up the
//     middleware chain to us. A `nil` error past the upstream-selection
//     point means upstream actually responded.
//
// We can't use `{http.reverse_proxy.status_code}` here — Caddy only sets
// it inside `handle_response` blocks, never for normal pass-through.
func classifyOrigin(repl *caddy.Replacer, servErr error) string {
	upstream := ""
	if repl != nil {
		upstream, _ = repl.GetString("http.reverse_proxy.upstream.address")
	}
	if upstream == "" {
		return OriginCluster
	}
	if servErr != nil && isHandlerError(servErr) {
		return OriginClusterProxyError
	}
	return OriginUpstream
}

// isHandlerError reports whether err (or anything it wraps) is a
// caddyhttp.HandlerError. reverse_proxy returns one of these on dial
// failure / timeout / client cancel, and the error bubbles up through
// every middleware on the chain.
func isHandlerError(err error) bool {
	var he caddyhttp.HandlerError
	return errors.As(err, &he)
}

// finalStatus returns the status code that will reach the client.
// When a downstream handler wrote the response, our recorder captured
// it. When a handler returned a HandlerError without writing (the
// normal reverse_proxy dial-failure path), Caddy's server-level error
// handler will write a status equal to the error's StatusCode AFTER our
// outer handler has returned — so we read it from the error here.
func finalStatus(w *recorder, servErr error) uint16 {
	if w.wrote {
		return uint16(w.status)
	}
	var he caddyhttp.HandlerError
	if errors.As(servErr, &he) && he.StatusCode != 0 {
		return uint16(he.StatusCode)
	}
	return uint16(w.status)
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
