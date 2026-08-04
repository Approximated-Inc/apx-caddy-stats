package apxstats

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
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
	if monitorSkip(r) {
		metricRequestsTotal.WithLabelValues("skipped_monitor").Inc()
		return next.ServeHTTP(w, r)
	}

	start := time.Now()

	wrapped := &recorder{ResponseWriter: w, status: 200}
	servErr := next.ServeHTTP(wrapped, r)

	recordCompletedRequest(h.app, h.logger, wrapped, r, servErr, start)
	return servErr
}

// monitorSkip reports whether r is one of Approximated's own URL monitor
// probes, carrying an `apx-monitor: true` request header. We don't record
// those — they're our health-check traffic and would inflate every
// customer's request_count + skew the status mix (a healthy vhost monitor
// is mostly 200s; an unhealthy one is mostly 5xxs from us, not the
// customer's real users). Checked before any wrapping work.
//
// Match against the exact "true" sentinel — same convention every
// other apx-monitor check in the Phoenix app uses. An earlier version
// matched any non-empty value as "defensive against the URL monitor
// changing the sentinel," but that opened a counter-bypass for any
// external client to mask their traffic from a customer's analytics
// dashboard with a one-line header injection. The exact match closes
// it.
func monitorSkip(r *http.Request) bool {
	return r.Header.Get("apx-monitor") == "true"
}

// recordCompletedRequest reads context off the request after
// next.ServeHTTP returns and feeds the counter map, the challenge-attempt
// map, the request_events track, and the unique-clients set. start is the
// time next.ServeHTTP was invoked; the elapsed duration is derived here.
//
// In legacy mode (mode_v2 off) request_events logs exactly one row per
// SERVED request (blocked/challenged requests excluded), preserving the
// original wire bytes. In mode_v2 every request — served, blocked,
// rate-limited, or challenged — is logged with a disposition; terminal
// challenges (no vhost_id) are logged under vhost_id=0 with a host field.
func recordCompletedRequest(app AppRef, logger *zap.Logger, w *recorder, r *http.Request, servErr error, start time.Time) {
	dur := time.Since(start)
	modeV2 := app.RequestEventsModeV2()

	// Challenge attempts record independently of vhost_id (see the original
	// comment): a served challenge is terminal so vhost_id is unset. Read
	// the outcome once — it also drives the request_event disposition below.
	outcome := readChallengeOutcome(r)
	if outcome != "" {
		app.RecordChallengeAttempt(challengeAttemptKey{
			vhost:   challengeVhost(r),
			ip:      securityClientIP(r),
			outcome: outcome,
		})
	}

	// Edge Verify attempts record independently of vhost_id too: the
	// Edge Verify edge handler sets `apx_verify_outcome` and, like the
	// challenge handler, may be terminal (vhost_id unset). The dimension is
	// (Host, path_bucket, outcome) — no per-client IP is recorded at the
	// edge for Edge Verify.
	edgeVerifyOutcome := readEdgeVerifyOutcome(r)
	if edgeVerifyOutcome != "" {
		app.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{
			vhost:      challengeVhost(r),
			pathBucket: pathBucket(r.URL.Path),
			outcome:    edgeVerifyOutcome,
		})
	}

	repl, _ := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	vhostID, ok := readVhostID(r)
	if !ok {
		// No vhost_id — the request didn't match a vhost route. Recording a
		// counter under vhost_id=0 would pollute aggregates, so skip it.
		metricRequestsTotal.WithLabelValues("no_vhost").Inc()
		// mode_v2 exception: a terminal challenge is served WITHOUT a
		// vhost_id (apx_challenge returns before the per-vhost vars handler
		// runs). Log it keyed by host, vhost_id=0, so the customer sees
		// challenge activity. Plain no-route requests stay dropped.
		if modeV2 && outcome != "" {
			reason := blockReason(repl, servErr)
			disp := deriveDisposition(reason, outcome)
			app.RecordRequestEvent(buildRequestEventRow(app, r, w, dur, servErr, repl, 0, challengeVhost(r), disp))
		}
		return
	}

	reason := blockReason(repl, servErr)
	origin := classifyOrigin(repl, servErr, reason)
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
		BytesOut:   responseBytes(w),
		DurationUs: durationUs,
		LatBucket:  BucketForUs(durationUs),
	}

	app.Record(k, d)
	metricRequestsTotal.WithLabelValues(origin).Inc()

	// request_events. In mode_v2, EVERY disposition is logged (served rows
	// unsampled, blocked/challenge rows sampled — decided in the recorder);
	// host is empty here because vhost_id resolves the vhost. In legacy
	// mode, only SERVED requests (reason == "") produce a row, in the
	// original wire shape (V2 unset).
	if modeV2 {
		disp := deriveDisposition(reason, outcome)
		app.RecordRequestEvent(buildRequestEventRow(app, r, w, dur, servErr, repl, k.VhostID, "", disp))
	} else if reason == "" {
		app.RecordRequestEvent(requestEventRow{
			TsUnixSec:   uint32(time.Now().UTC().Unix()),
			VhostID:     k.VhostID,
			ClientIP:    securityClientIP(r),
			ForwardedIP: forwardedIP(r),
			FrontProxy:  frontProxy(r),
			Method:      k.Method,
			Path:        capPath(r.URL.Path),
			PathBucket:  pathBucket(r.URL.Path),
			Status:      k.Status,
			HTTPVersion: httpVersionOrUnknown(r),
			UA:          capUA(r.UserAgent()),
			Origin:      origin,
			BytesIn:     requestBytes(r),
			BytesOut:    responseBytes(w),
			DurationUs:  durationUs,
		})
	}

	// Unique-clients tracking. Skipped entirely when the salt isn't
	// configured (returns "" — see StatsApp.HashSalt). Hash inputs:
	// client IP + user-agent + salt. Best-effort identity — same UA
	// from the same IP behind a NAT will collapse, mobile clients
	// rotating IPs will split. Good enough for "rough number of
	// distinct clients in this window."
	if salt := app.HashSalt(); salt != "" {
		hash := ClientHash(clientIP(r), r.UserAgent(), salt)
		app.RecordUnique(k.TsUnixMin, k.VhostID, hash)
	}
}

// buildRequestEventRow assembles a mode_v2 request_event row. vhostID is 0
// for terminal challenges; host is the lowercased/port-stripped Host header
// (capped) for those rows and "" when a vhost_id resolves the vhost.
// disposition is one of the disp* constants. SampleRate is stamped later by
// the recorder. Origin/reason are recomputed from the same inputs the
// counter path used, so the two stay consistent.
func buildRequestEventRow(app AppRef, r *http.Request, w *recorder, dur time.Duration, servErr error, repl *caddy.Replacer, vhostID uint32, host, disposition string) requestEventRow {
	reason := blockReason(repl, servErr)
	origin := classifyOrigin(repl, servErr, reason)
	now := time.Now().UTC()
	return requestEventRow{
		TsUnixSec:   uint32(now.Unix()),
		TsUnixMs:    now.UnixMilli(),
		VhostID:     vhostID,
		ClientIP:    securityClientIP(r),
		ForwardedIP: forwardedIP(r),
		FrontProxy:  frontProxy(r),
		Method:      methodOrUnknown(r.Method),
		Path:        capPath(r.URL.Path),
		PathBucket:  pathBucket(r.URL.Path),
		Status:      finalStatus(w, servErr),
		HTTPVersion: httpVersionOrUnknown(r),
		UA:          capUA(r.UserAgent()),
		Origin:      origin,
		BytesIn:     requestBytes(r),
		BytesOut:    responseBytes(w),
		DurationUs:  uint64(dur.Microseconds()),
		MachineID:   truncateBytes(app.MachineID(), 64),
		MachineSeq:  nextMachineSeq(),
		Disposition: disposition,
		Host:        host,
		V2:          true,
	}
}

// clientIP returns the best-guess client IP for hashing purposes. Prefers
// the rightmost X-Forwarded-For entry (the request came in through a
// trusted proxy chain) but falls back to RemoteAddr when no XFF header
// is set. Strictly used for hashing — not for any access decision — so
// trust assumptions are looser than for security-sensitive callers.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Last entry is the client closest to the trusted proxy boundary.
		// Find the last comma; the bit after it (trimmed) is the IP.
		if i := lastIndexByte(xff, ','); i >= 0 {
			return trimSpace(xff[i+1:])
		}
		return trimSpace(xff)
	}
	return r.RemoteAddr
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
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

// readChallengeOutcome reads the `apx_challenge_outcome` request var set
// by the apx_challenge handler — one of "issued" | "passed" |
// "passed_recently" | "failed", or "" when no challenge handler ran.
// Readable here because apx_stats is the OUTERMOST handler wrapping the
// subroute: the challenge handler mutates the shared vars map via
// caddyhttp.SetVar before returning, and our deferred record() runs after
// next.ServeHTTP returns, so the var is visible.
func readChallengeOutcome(r *http.Request) string {
	v := caddyhttp.GetVar(r.Context(), "apx_challenge_outcome")
	s, _ := v.(string)
	return s
}

// readEdgeVerifyOutcome reads the `apx_verify_outcome` request var set by
// the Edge Verify edge handler — one of "passed" | "missing" | "invalid" |
// "expired" | "replayed", or "" when no Edge Verify handler ran.
// Readable here for the same reason as readChallengeOutcome: apx_stats is
// the outermost handler wrapping the subroute, so vars set by inner
// handlers before returning are visible in our deferred record().
func readEdgeVerifyOutcome(r *http.Request) string {
	v := caddyhttp.GetVar(r.Context(), "apx_verify_outcome")
	s, _ := v.(string)
	return s
}

// challengeVhost returns the lowercased Host header with any :port
// stripped, width-capped to challengeVhostMaxBytes. A served challenge is
// terminal (the apx_challenge handler returns without calling next), so
// the per-vhost vars handler never runs and vhost_id is unset — the
// challenge_attempt dimension is therefore the Host string, NOT vhost_id.
//
// The result may still slice a request-owned backing (truncateBytes is
// copy-free under the cap, and r.Host can be a slice of the request line
// for absolute-form URIs); RecordChallengeAttempt clones the key strings
// on first insert, so steady-state increments stay copy-free.
func challengeVhost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return truncateBytes(strings.ToLower(host), challengeVhostMaxBytes)
}

// blockReason reports why Caddy itself blocked this request before it
// reached the upstream — "waf", "rate_limit", or "" (not blocked). It
// feeds both the request_counters origin (cluster_blocked) and the
// request_events served-only filter, so the two stay consistent.
//
// An explicit {http.vars.apx_block_reason} wins when a handler sets it
// (override / future-proofing). Otherwise we infer from the error the
// blocking handler returned: apx_stats is the OUTERMOST handler, so a
// coraza interruption or a rate_limit reject bubbles up to us as servErr
// (a caddyhttp.HandlerError) even though those handlers terminate the
// chain before reverse_proxy:
//
//   - coraza (block mode) returns HandlerError{Err: errInterruptionTriggered}
//     whose message is "interruption triggered" (coraza-caddy v2.5.0,
//     coraza.go / interceptor.go). We key on that string.
//   - the apx rate_limit fork returns caddyhttp.Error(429, nil).
//
// A reverse_proxy failure also returns a HandlerError, but with a 5xx/499
// status and a proxy error message — never these signals — so it is
// classified as cluster_proxy_error, not a block. An origin's own 429 is
// served (response written, servErr nil) and never reaches here.
func blockReason(repl *caddy.Replacer, servErr error) string {
	if repl != nil {
		if reason, _ := repl.GetString("http.vars.apx_block_reason"); reason != "" {
			return reason
		}
	}

	var he caddyhttp.HandlerError
	if !errors.As(servErr, &he) {
		return ""
	}
	if strings.Contains(he.Error(), "interruption triggered") {
		return "waf"
	}
	if he.StatusCode == http.StatusTooManyRequests {
		return "rate_limit"
	}
	return ""
}

// classifyOrigin maps a finished request to one of four origin classes.
//
//   - upstream: reverse_proxy attempted and the upstream returned. Caddy
//     passed the response through to the client.
//   - cluster_proxy_error: reverse_proxy attempted but failed (dial
//     refused, timeout, no upstream selected, etc.). Caddy synthesized
//     the response (typically 502 / 504 / 503 / 499).
//   - cluster_blocked: Caddy deliberately blocked the request before
//     reaching upstream — WAF block, rate-limit reject, etc. Detected
//     via the `apx_block_reason` request var set by the blocking
//     handler. Distinct from `cluster` so customer-facing dashboards
//     don't surface WAF spikes as "cluster failures."
//   - cluster: reverse_proxy was never reached and we didn't see a
//     block reason. Caddy generated the response itself (404 from no
//     matching route, redirect, error page, etc.).
//
// Signal sources:
//
//   - `{http.vars.apx_block_reason}` — set by WAF / rate-limit /
//     similar handlers when they actively block a request. Presence
//     (any non-empty value) classifies the row as `cluster_blocked`.
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
//
// blockReason (computed once by the caller) decides cluster_blocked; an
// empty reason falls through to the upstream/cluster classification below.
func classifyOrigin(repl *caddy.Replacer, servErr error, blockReason string) string {
	if blockReason != "" {
		return OriginClusterBlocked
	}

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
//
// Returns the net/http package CONSTANT for matched verbs — never m
// itself. On HTTP/1.1, m is a slice of the full request line (method +
// URI + proto share one backing array), and the result is buffered in
// the counter map Key and the request_events rows until flush; returning
// m would pin the whole attacker-length-controlled line (~1MB under a
// long-URI flood) per buffered entry while the governor's byte
// accounting counts only len("POST"). Non-standard verbs clamp to the
// static "OTHER" sentinel, which is equally pin-free.
func methodOrUnknown(m string) string {
	switch m {
	case http.MethodGet:
		return http.MethodGet
	case http.MethodPost:
		return http.MethodPost
	case http.MethodPut:
		return http.MethodPut
	case http.MethodPatch:
		return http.MethodPatch
	case http.MethodDelete:
		return http.MethodDelete
	case http.MethodHead:
		return http.MethodHead
	case http.MethodOptions:
		return http.MethodOptions
	case http.MethodConnect:
		return http.MethodConnect
	case http.MethodTrace:
		return http.MethodTrace
	}
	return "OTHER"
}

// requestBytes approximates the inbound request size: request line +
// headers + body. Body uses Content-Length when set (chunked or
// unknown-length bodies contribute 0 from the body — counting actual
// bytes off r.Body would require buffering the stream). Header sizes
// are sums of `Name: Value\r\n` per entry. TLS framing and HTTP/2
// HPACK compression aren't accounted for; this is a logical-message
// size, useful for "how much data was the cluster shown" — not a wire
// counter.
func requestBytes(r *http.Request) uint64 {
	// Request line: METHOD SP URI SP PROTO CRLF
	n := uint64(len(r.Method)) + 1 + uint64(len(r.RequestURI)) + 1 + uint64(len(r.Proto)) + 2
	for name, vals := range r.Header {
		for _, v := range vals {
			n += uint64(len(name)) + 2 + uint64(len(v)) + 2 // "Name: Value\r\n"
		}
	}
	n += 2 // blank line terminating headers
	if r.ContentLength > 0 {
		n += uint64(r.ContentLength)
	}
	return n
}

// responseBytes approximates the outbound response size: status line +
// headers + body. Body comes from the recorder's per-Write byte count,
// which is exact. Headers are approximated the same way as the request
// side. If the response was never written (HandlerError path; Caddy's
// outer handler will write a synthesized status later), this returns
// 0 — the synthesized response is small (~200 bytes) and outside our
// observation point.
//
// Hijacked connections (WebSocket upgrades, raw-TCP via reverse_proxy)
// also return 0: at the time of Hijack() the upgrade response hadn't
// been written yet via our recorder, and post-hijack bytes pass through
// the bare net.Conn we don't see. Counting status-line + headers from
// `w.Header()` on a hijacked connection would fabricate ~100-200 bytes
// per upgrade — observed inflation on customers using a lot of
// WebSocket traffic. Return 0 to be honest.
func responseBytes(w *recorder) uint64 {
	if !w.wrote || w.hijacked {
		return 0
	}
	// Status line: HTTP/1.1 NNN STATUS_TEXT CRLF — Proto isn't on the
	// recorder so use a fixed-length approximation. The few-byte error
	// is fine at the cluster-aggregate scale we care about.
	n := uint64(len("HTTP/1.1 ")) + 3 + 1 + uint64(len(http.StatusText(w.status))) + 2
	for name, vals := range w.Header() {
		for _, v := range vals {
			n += uint64(len(name)) + 2 + uint64(len(v)) + 2
		}
	}
	n += 2 // blank line terminating headers
	n += uint64(w.bytes)
	return n
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
