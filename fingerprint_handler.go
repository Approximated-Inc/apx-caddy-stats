package apxstats

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// JA3 / JA4 cx var names set by caddy-l4 l4tls.MatchTLS (Chunk 3b).
// Pinned to the contract in scratchpad #27 / caddy-l4 matcher.go.
const (
	TLSJA3Var = "tls_ja3"
	TLSJA4Var = "tls_ja4"
)

// FingerprintHandler records the JA3/JA4 fingerprint of each accepted L4
// TLS connection. Pure recording side-effect — always calls next.Handle.
// Wire AFTER l4tls.MatchTLS (the cx vars are only set after MatchTLS runs).
type FingerprintHandler struct {
	logger *zap.Logger
	app    *StatsApp
}

func (*FingerprintHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.apx_l4_fingerprint_stats",
		New: func() caddy.Module { return new(FingerprintHandler) },
	}
}

func (h *FingerprintHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.app != nil {
		// Test injection path — already wired.
		return nil
	}

	app, err := ctx.App("apx_stats")
	if err != nil {
		return fmt.Errorf("apx_l4_fingerprint_stats handler requires apx_stats app: %w", err)
	}

	sa, ok := app.(*StatsApp)
	if !ok {
		return fmt.Errorf("apx_l4_fingerprint_stats handler: unexpected app type %T", app)
	}

	h.app = sa
	return nil
}

// UnmarshalCaddyfile satisfies the Caddyfile interface. The handler
// takes no Caddyfile arguments — it's a pure recorder.
func (h *FingerprintHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (h *FingerprintHandler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	return next.Handle(cx) // recording added in 3c.5
}

// Interface guards.
var (
	_ caddy.Provisioner     = (*FingerprintHandler)(nil)
	_ caddyfile.Unmarshaler = (*FingerprintHandler)(nil)
	_ layer4.NextHandler    = (*FingerprintHandler)(nil)
)
