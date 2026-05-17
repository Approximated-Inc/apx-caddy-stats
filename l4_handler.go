package apxstats

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// L4SniReplacerKey is the Caddy replacer key under which `l4tls.MatchTLS`
// publishes the SNI parsed from the TLS ClientHello. Hardcoded here
// (rather than imported) because the l4tls package's key constants are
// unexported. Pinned to the contract in
// caddy-l4/modules/l4tls/matcher.go:222-226.
const L4SniReplacerKey = "l4.tls.server_name"

// L4Handler is a layer4 handler module that records the SNI of each
// accepted L4 TLS connection into the StatsApp's L4 SNI counter map.
// Always calls next.Handle — it's a recording side-effect, not a gate.
//
// Wire into the Caddy layer4 forward route AFTER `l4tls.MatchTLS` (the
// SNI replacer var is only set after MatchTLS runs). Approximated's
// `caddy_config_files.ex` emits this handler with the appropriate
// route order.
type L4Handler struct {
	logger *zap.Logger
	app    *StatsApp
}

func (*L4Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.apx_l4_stats",
		New: func() caddy.Module { return new(L4Handler) },
	}
}

func (h *L4Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.app != nil {
		// Test injection path — already wired.
		return nil
	}

	app, err := ctx.App("apx_stats")
	if err != nil {
		return fmt.Errorf("apx_l4_stats handler requires apx_stats app: %w", err)
	}

	sa, ok := app.(*StatsApp)
	if !ok {
		return fmt.Errorf("apx_l4_stats handler: unexpected app type %T", app)
	}

	h.app = sa
	return nil
}

// UnmarshalCaddyfile satisfies the Caddyfile interface. The handler
// takes no Caddyfile arguments — it's a pure recorder.
func (h *L4Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (h *L4Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	sni := readSNIFromCx(cx)
	h.app.RecordL4Sni(sni)
	return next.Handle(cx)
}

// readSNIFromCx pulls the SNI from the Caddy replacer where
// `l4tls.MatchTLS` publishes it. Returns "" if the replacer doesn't
// have the key (handler wired into a route that didn't go through
// MatchTLS, non-TLS traffic, etc.); RecordL4Sni maps that to the
// L4SniEmptySNI sentinel.
func readSNIFromCx(cx *layer4.Connection) string {
	repl := cx.Replacer()
	if repl == nil {
		return ""
	}
	v, ok := repl.GetString(L4SniReplacerKey)
	if !ok {
		return ""
	}
	return v
}

// Interface guards.
var (
	_ caddy.Provisioner     = (*L4Handler)(nil)
	_ caddyfile.Unmarshaler = (*L4Handler)(nil)
	_ layer4.NextHandler    = (*L4Handler)(nil)
)
