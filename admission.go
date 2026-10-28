package apxstats

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// AdmissionHandler (http.handlers.apx_admission) answers a fast 503 with
// Retry-After instead of queueing when the node is starved. Phoenix places
// it right after apx_stats in the stats wrapper, before trace, policy and
// vhost routing, which is the CPU worth saving. Its config is
// apps.apx_stats.overload.admission; the handler itself takes none.
type AdmissionHandler struct{}

func (AdmissionHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.apx_admission", New: func() caddy.Module { return new(AdmissionHandler) }}
}

// Provision loads the apx_stats app, which owns the overload config.
func (h *AdmissionHandler) Provision(ctx caddy.Context) error {
	if _, err := ctx.App("apx_stats"); err != nil {
		return fmt.Errorf("apx_admission handler requires apx_stats app: %w", err)
	}
	return nil
}

// Admission classes, most protected first.
const (
	admitP0 = iota // platform: challenge, ACME, health
	admitP1        // HTML navigation
	admitP2        // everything else
	admitP3        // static assets
)

// admissionCompletions counts admitted requests that finished and
// admissionLatencyNs sums their durations; the sampler turns them into the
// rate and latency target of the adaptive limit.
var (
	admissionCompletions atomic.Uint64
	admissionLatencyNs   atomic.Uint64
)

func (h AdmissionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rt := overload.cfg.Load()
	if rt == nil || !rt.admissionLive {
		return next.ServeHTTP(w, r)
	}
	start := time.Now()
	inflight := admissionInflight.Add(1) - 1 // others already in flight
	level := overload.level.Load()
	if level < 2 && inflight < int64(rt.hardLimit) {
		// Fast path: no classification, no allocation.
		return admit(w, r, next, start)
	}
	class := classifyAdmission(r)
	shed, hard := admissionShouldShed(class, inflight, level, admissionLimitNow.Load(), int64(rt.hardLimit))
	if !shed {
		return admit(w, r, next, start)
	}
	if !rt.admitEnforce {
		overloadCounts.wouldShed.Add(1)
		return admit(w, r, next, start)
	}
	admissionInflight.Add(-1)
	overloadCounts.shed[class].Add(1)
	if hard {
		hardCapHit.Store(true)
	}
	writeShed(w)
	return nil
}

// admit serves an admitted request and releases its in-flight slot. A
// request that may become a long-lived stream (a WebSocket or CONNECT
// upgrade, or an event-stream Accept) is counted and shed like any other:
// those headers are the client's, so they can't buy a pass. Its slot is
// released early, without a completion, once the response proves to be a
// stream (101, a 2xx CONNECT, or a text/event-stream body).
func admit(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, start time.Time) error {
	if !admissionStreamCandidate(r) {
		defer admissionDone(start)
		return next.ServeHTTP(w, r)
	}
	sw := &admissionStreamWriter{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}, connect: r.Method == http.MethodConnect}
	defer func() {
		if !sw.released {
			admissionDone(start)
		}
	}()
	return next.ServeHTTP(sw, r)
}

func admissionDone(start time.Time) {
	admissionInflight.Add(-1)
	admissionCompletions.Add(1)
	admissionLatencyNs.Add(uint64(time.Since(start)))
}

// admissionStreamCandidate: requests whose response may be a long-lived
// stream, which would otherwise hold an in-flight slot for hours.
func admissionStreamCandidate(r *http.Request) bool {
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

// admissionStreamWriter releases the in-flight slot when the response turns
// out to be a stream. Hijack and Flush reach the real writer via Unwrap.
type admissionStreamWriter struct {
	*caddyhttp.ResponseWriterWrapper
	connect     bool
	wroteHeader bool
	released    bool
}

func (w *admissionStreamWriter) WriteHeader(code int) {
	if !w.wroteHeader && (code == http.StatusSwitchingProtocols || code >= 200) {
		w.wroteHeader = true
		if code == http.StatusSwitchingProtocols || (w.connect && code < 300) ||
			strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
			w.released = true
			admissionInflight.Add(-1)
		}
	}
	w.ResponseWriterWrapper.WriteHeader(code)
}

func (w *admissionStreamWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriterWrapper.Write(b)
}

// admissionShouldShed decides for a classified request. limit is the
// adaptive limit (0 when none applies). At level 2: P3 sheds at
// inflight ≥ 0.5 L, P2 at ≥ L, P1 at ≥ 1.5 L. The hard cap applies at any
// level: P2/P3 at hard, P1 at 1.25 × hard. P0 is never shed.
func admissionShouldShed(class int, inflight int64, level int32, limit, hardLimit int64) (shed, hard bool) {
	if class == admitP0 {
		return false, false
	}
	hardAt := hardLimit
	if class == admitP1 {
		hardAt = hardLimit + hardLimit/4
	}
	if inflight >= hardAt {
		return true, true
	}
	if level < 2 || limit <= 0 {
		return false, false
	}
	switch class {
	case admitP3:
		return inflight*2 >= limit, false
	case admitP2:
		return inflight >= limit, false
	default: // P1
		return inflight*2 >= limit*3, false
	}
}

// adaptiveLimit is Little's law: clamp(ceil(completions/s × target), min,
// hard). With the thresholds above, P2 sheds once mean latency reaches the
// target, so target is relative to this node's normal latency
// (latencyTarget), not a fixed second: an origin that always takes 1.2 s is
// not overload by itself.
func adaptiveLimit(completionsPerS float64, target time.Duration, minLimit, hardLimit int) int {
	l := int(math.Ceil(completionsPerS * target.Seconds()))
	if l < minLimit {
		l = minLimit
	}
	if l > hardLimit {
		l = hardLimit
	}
	return l
}

func classifyAdmission(r *http.Request) int {
	p := r.URL.Path
	if strings.HasPrefix(p, "/__apx_") || strings.HasPrefix(p, "/.well-known/acme-challenge/") ||
		p == "/healthy" || strings.HasPrefix(p, "/apxflyhealthcheck") {
		return admitP0
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		h := r.Header
		if h.Get("Sec-Fetch-Mode") == "navigate" || h.Get("Sec-Fetch-Dest") == "document" ||
			strings.HasPrefix(h.Get("Accept"), "text/html") {
			return admitP1
		}
		if staticExt(p) {
			return admitP3
		}
	}
	return admitP2
}

var (
	shedBody          = []byte("503 node overloaded, retry in a moment\n")
	shedRetryAfter    = [3][]string{{"1"}, {"2"}, {"3"}}
	shedNoStore       = []string{"no-store"}
	shedOverloadFlag  = []string{"1"}
	shedContentType   = []string{"text/plain; charset=utf-8"}
	shedContentLength = []string{fmt.Sprint(len(shedBody))}
)

// writeShed writes the 503. The connection stays open: a reconnect costs a
// TLS handshake, the most expensive thing to make a starved node do.
func writeShed(w http.ResponseWriter) {
	h := w.Header()
	h["Retry-After"] = shedRetryAfter[rand.IntN(3)]
	h["Cache-Control"] = shedNoStore
	h["Apx-Overload"] = shedOverloadFlag
	h["Content-Type"] = shedContentType
	h["Content-Length"] = shedContentLength
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(shedBody)
}

// completionRate is the sampler's 10 s EWMA of admitted completions/s,
// held up by a peak that decays with a 60 s time constant. Shed requests
// never complete, so the bare EWMA would follow the throughput shedding
// itself removed and ratchet the limit down to min_limit.
type completionRate struct {
	last    uint64
	ewma    float64
	peak    float64
	started bool
}

func (c *completionRate) sample(total uint64, dt time.Duration) float64 {
	if !c.started || dt <= 0 || dt > 10*time.Second {
		c.last, c.started = total, true
		return math.Max(c.ewma, c.peak)
	}
	inst := float64(total-c.last) / dt.Seconds()
	c.last = total
	alpha := 1 - math.Exp(-dt.Seconds()/10)
	c.ewma += alpha * (inst - c.ewma)
	c.peak = math.Max(c.ewma, c.peak*math.Exp(-dt.Seconds()/60))
	return c.peak
}

// Latency target bounds: never below the 1 s of the original design, never
// so far out that admission stops protecting the node.
const (
	minLatencyTarget = time.Second
	maxLatencyTarget = 10 * time.Second
)

// latencyTarget learns this node's normal mean admitted latency, only while
// the level is 0 (5 min EWMA, from samples of at least 20 completions), and
// returns clamp(2 × normal, 1 s, 10 s): P2 sheds once latency has doubled.
// Unknown (no normal-time samples yet) is 1 s.
type latencyTarget struct {
	lastN, lastNs uint64
	normal        float64 // seconds; 0 unknown
	started       bool
}

func (l *latencyTarget) sample(completions, latencyNs uint64, dt time.Duration, normal bool) time.Duration {
	dn, dns := completions-l.lastN, latencyNs-l.lastNs
	ok := l.started && dt > 0 && dt <= 10*time.Second
	l.lastN, l.lastNs, l.started = completions, latencyNs, true
	if ok && normal && dn >= 20 {
		mean := float64(dns) / float64(dn) / 1e9
		if l.normal == 0 {
			l.normal = mean
		} else {
			l.normal += (1 - math.Exp(-dt.Seconds()/300)) * (mean - l.normal)
		}
	}
	t := time.Duration(2 * l.normal * float64(time.Second))
	return min(max(t, minLatencyTarget), maxLatencyTarget)
}

var (
	_ caddy.Provisioner           = (*AdmissionHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*AdmissionHandler)(nil)
)
