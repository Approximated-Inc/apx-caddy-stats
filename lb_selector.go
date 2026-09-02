package apxstats

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func init() {
	caddy.RegisterModule(LatencySelection{})
}

// LatencySelection picks the available upstream with the lowest decayed
// latency EWMA, scaled by in-flight requests so a queue building up on the
// current favourite pushes traffic elsewhere before latency has visibly
// risen.
//
// This is a soft preference, not an ejection. When every upstream is slow
// it still returns the least-bad one. A latency *threshold* would mark
// them all unavailable and return nil, turning a slow site into a 503.
type LatencySelection struct{}

// CaddyModule returns the Caddy module information.
func (LatencySelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.apx_latency",
		New: func() caddy.Module { return new(LatencySelection) },
	}
}

// Select returns the lowest-scoring available upstream, or nil if none is
// available (in which case Caddy's own no-upstream handling applies).
func (LatencySelection) Select(pool reverseproxy.UpstreamPool, _ *http.Request, _ http.ResponseWriter) *reverseproxy.Upstream {
	return lbSelectLowest(pool, func(u *reverseproxy.Upstream) bool { return u.Available() })
}

// lbSelectLowest carries the scoring logic with availability injected, so
// the unavailable-upstream case is testable from outside the reverseproxy
// package.
func lbSelectLowest(pool reverseproxy.UpstreamPool, available func(*reverseproxy.Upstream) bool) *reverseproxy.Upstream {
	var best *reverseproxy.Upstream
	var bestScore float64

	for _, up := range pool {
		if !available(up) {
			continue
		}
		// An unsampled upstream scores 0, so a cold pool resolves to the
		// first available entry — exactly the "first" policy's behaviour,
		// which is what these vhosts do today.
		ewma, _ := lbScore(up.Dial)
		score := ewma * float64(up.NumRequests()+1)

		if best == nil || score < bestScore {
			best, bestScore = up, score
		}
	}
	return best
}

var _ reverseproxy.Selector = (*LatencySelection)(nil)
