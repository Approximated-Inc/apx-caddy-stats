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

// admissionCompletions counts admitted requests that finished; the sampler
// turns it into a 10 s EWMA rate for the adaptive limit.
var admissionCompletions atomic.Uint64

func (h AdmissionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rt := overload.cfg.Load()
	if rt == nil || !rt.admissionLive || admissionPassthrough(r) {
		return next.ServeHTTP(w, r)
	}
	inflight := admissionInflight.Add(1) - 1 // others already in flight
	level := overload.level.Load()
	if level < 2 && inflight < int64(rt.hardLimit) {
		// Fast path: no classification, no allocation.
		defer admissionDone()
		return next.ServeHTTP(w, r)
	}
	class := classifyAdmission(r)
	shed, hard := admissionShouldShed(class, inflight, level, admissionLimitNow.Load(), int64(rt.hardLimit))
	if !shed {
		defer admissionDone()
		return next.ServeHTTP(w, r)
	}
	if !rt.admitEnforce {
		overloadCounts.wouldShed.Add(1)
		defer admissionDone()
		return next.ServeHTTP(w, r)
	}
	admissionInflight.Add(-1)
	overloadCounts.shed[class].Add(1)
	if hard {
		hardCapHit.Store(true)
	}
	writeShed(w)
	return nil
}

func admissionDone() {
	admissionInflight.Add(-1)
	admissionCompletions.Add(1)
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

// adaptiveLimit is Little's law with a 1 s target:
// clamp(ceil(completions/s × 1 s), min, hard).
func adaptiveLimit(completionsPerS float64, minLimit, hardLimit int) int {
	l := int(math.Ceil(completionsPerS))
	if l < minLimit {
		l = minLimit
	}
	if l > hardLimit {
		l = hardLimit
	}
	return l
}

// admissionPassthrough: long-lived streams are neither counted nor shed.
func admissionPassthrough(r *http.Request) bool {
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
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

// completionRate is the sampler's 10 s EWMA of admitted completions/s.
type completionRate struct {
	last    uint64
	ewma    float64
	started bool
}

func (c *completionRate) sample(total uint64, dt time.Duration) float64 {
	if !c.started || dt <= 0 || dt > 10*time.Second {
		c.last, c.started = total, true
		return c.ewma
	}
	inst := float64(total-c.last) / dt.Seconds()
	c.last = total
	alpha := 1 - math.Exp(-dt.Seconds()/10)
	c.ewma += alpha * (inst - c.ewma)
	return c.ewma
}

var (
	_ caddy.Provisioner           = (*AdmissionHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*AdmissionHandler)(nil)
)
