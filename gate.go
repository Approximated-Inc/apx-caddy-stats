package apxstats

import (
	"fmt"
	"net/http"
	"time"

	apxapp "github.com/Approximated-Inc/apx-caddy-stats/apx"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// GateHandler is the unified per-request gate, installed once at the top of
// the global handler chain (the slot apx_stats occupies today). It does two
// jobs per request:
//
//  1. Registers the lazy geoip2.* replacer provider (geoprovider.go) so
//     every inner consumer — the Geoip-Country header route, geo edge
//     rules, customer placeholders, and our own readCountry — resolves the
//     fork's placeholder surface without an eager per-request decode.
//  2. Records stats byte-identically to StatsHandler: same monitor skip,
//     same recorder wrap, same recordCompletedRequest on the response path.
//
// The provider is registered for EVERY request, including monitor probes —
// today's geoip2 route runs for monitors too, so placeholder resolvability
// must not depend on the recording skip. Registration is a closure append;
// all lookup work stays lazy until a geoip2.* key is actually resolved.
type GateHandler struct {
	// Geo selects the client-IP mode for geo lookups, mirroring the
	// caddy-geoip2 fork's Enable values: "strict" (RemoteAddr only),
	// "wild" (leftmost X-Forwarded-For when present — prod value),
	// "trusted_proxies", or "off"/"false"/"0" (no lookup; fixed keys
	// resolve as empty strings). Empty/absent maps to "off" — NEVER to
	// the fork's implicit trusted_proxies default: an unconfigured gate
	// must behave like a disabled geoip2 handler.
	Geo string `json:"geo,omitempty"`

	logger *zap.Logger
	app    AppRef      // stats sink (apps.apx_stats)
	apx    *apxapp.App // geo reader (apps.apx)
}

// CaddyModule registers the handler at "http.handlers.apx_gate".
func (*GateHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_gate",
		New: func() caddy.Module { return new(GateHandler) },
	}
}

// Provision resolves both apps the gate composes. Uses AppIfConfigured —
// NOT ctx.App — because absence must be a hard config error: ctx.App would
// silently instantiate an empty app (no flush loop, no geo DB), which means
// dropped counters and empty geo. The generator always emits both apps.
func (g *GateHandler) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger()
	if g.app == nil {
		appVal, err := ctx.AppIfConfigured("apx_stats")
		if err != nil {
			return fmt.Errorf("apx_gate requires the apx_stats app: %w", err)
		}
		sa, ok := appVal.(*StatsApp)
		if !ok {
			return fmt.Errorf("apx_gate: unexpected apx_stats app type %T", appVal)
		}
		g.app = sa
	}
	if g.apx == nil {
		appVal, err := ctx.AppIfConfigured("apx")
		if err != nil {
			return fmt.Errorf("apx_gate requires the apx app: %w", err)
		}
		aa, ok := appVal.(*apxapp.App)
		if !ok {
			return fmt.Errorf("apx_gate: unexpected apx app type %T", appVal)
		}
		g.apx = aa
	}
	return nil
}

// geoProviderMode maps the Geo config field to an explicit provider mode.
// "" is never passed through: the fork treats "" as its trusted_proxies
// default (lookup still runs), but an unconfigured gate must be off.
func (g *GateHandler) geoProviderMode() string {
	if g.Geo == "" {
		return "off"
	}
	return g.Geo
}

// ServeHTTP mirrors StatsHandler.ServeHTTP exactly for recording; the only
// addition is the geo provider registration, which happens before the
// monitor-skip check so geoip2.* placeholders resolve on monitor traffic
// too (parity with today's geoip2 route position).
func (g *GateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Map(newGeoProvider(g.apx, g.geoProviderMode(), r))
	}

	if monitorSkip(r) {
		metricRequestsTotal.WithLabelValues("skipped_monitor").Inc()
		return next.ServeHTTP(w, r)
	}

	start := time.Now()

	wrapped := &recorder{ResponseWriter: w, status: 200}
	servErr := next.ServeHTTP(wrapped, r)

	recordCompletedRequest(g.app, g.logger, wrapped, r, servErr, start)
	return servErr
}

var (
	_ caddy.Provisioner           = (*GateHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*GateHandler)(nil)
)
