package apxstats

import (
	"net/http"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
)

// OverloadBridge is the in-process interface the Coraza fork discovers as
// module apx.overload (the apx.coraza_privacy pattern: no Go import between
// the repos). It carries no state of its own; it reads the package-level
// controller.
type OverloadBridge struct{}

func init() { caddy.RegisterModule(OverloadBridge{}) }

func (OverloadBridge) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "apx.overload", New: func() caddy.Module { return new(OverloadBridge) }}
}

// SkipWAF reports whether the WAF should not evaluate r. staticOnly is the
// block-mode policy: only wafSkippableStatic requests are skipped. Observe
// mode counts would-skip and returns false. At level 0 this is one atomic
// load and a branch.
func (b *OverloadBridge) SkipWAF(r *http.Request, staticOnly bool) bool {
	if overload.level.Load() < 1 {
		return false
	}
	rt := overload.cfg.Load()
	if rt == nil || (!rt.wafEnforce && !rt.wafObserve) {
		return false
	}
	if staticOnly && !wafSkippableStatic(r) {
		return false
	}
	if rt.wafObserve {
		overloadCounts.wafWouldSkip.Add(1)
		metricOverloadWAFSkips.WithLabelValues("would_skip").Inc()
		return false
	}
	if staticOnly {
		overloadCounts.wafSkippedStatic.Add(1)
		metricOverloadWAFSkips.WithLabelValues("static").Inc()
	} else {
		overloadCounts.wafSkippedDetect.Add(1)
		metricOverloadWAFSkips.WithLabelValues("detect").Inc()
	}
	return true
}

// overloadCounts are cumulative; node_state rows carry per-minute deltas.
var overloadCounts struct {
	wafSkippedDetect atomic.Uint64
	wafSkippedStatic atomic.Uint64
	wafWouldSkip     atomic.Uint64
	shed             [4]atomic.Uint64 // by admission class P0..P3
	wouldShed        atomic.Uint64
}
