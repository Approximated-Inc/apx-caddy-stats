package apxstats

import (
	"crypto/tls"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

// JA4Matcher computes the JA4 fingerprint for a TLS handshake, hands it to the
// HTTP layer, and reports whether it is blocklisted.
//
// IMPORTANT: this is a caddytls ConnectionMatcher. Returning false means "this
// policy does not apply", NOT "allow" — if no policy matches, caddytls drops
// the connection. The generated config must always place a catch-all {} policy
// after this one. See caddytls/connpolicy.go:126-138.
//
// Do NOT register or reference this under layer4.matchers.tls:
// l4tls.ClientHelloInfo shadows the embedded Extensions field, so an
// L4-invoked matcher would see Extensions == nil and compute a wrong JA4.
type JA4Matcher struct {
	// Blocklist is the set of JA4 strings that match. Empty means the matcher
	// never matches — record-only mode.
	Blocklist []string `json:"blocklist,omitempty"`

	set      map[string]struct{}
	app      *StatsApp
	registry *ja4Registry
	logger   *zap.Logger
}

func (*JA4Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.apx_ja4",
		New: func() caddy.Module { return new(JA4Matcher) },
	}
}

func (m *JA4Matcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if m.app == nil {
		app, err := ctx.App("apx_stats")
		if err != nil {
			return fmt.Errorf("apx_ja4 matcher requires apx_stats app: %w", err)
		}
		sa, ok := app.(*StatsApp)
		if !ok {
			return fmt.Errorf("apx_ja4 matcher: unexpected app type %T", app)
		}
		m.app = sa
	}
	if m.registry == nil {
		m.registry = m.app.JA4Registry()
	}
	if err := m.compile(); err != nil {
		return err
	}
	if m.logger != nil {
		// Which mode a cluster is in is the fact you want during a rollout:
		// an empty set is record-only and can never select this policy.
		m.logger.Info("apx_ja4 matcher provisioned",
			zap.Int("blocklist_size", len(m.set)),
			zap.Bool("record_only", len(m.set) == 0))
	}
	return nil
}

// compile builds the blocklist lookup set.
func (m *JA4Matcher) compile() error {
	m.set = make(map[string]struct{}, len(m.Blocklist))
	for _, ja4 := range m.Blocklist {
		if ja4 == "" {
			continue
		}
		m.set[ja4] = struct{}{}
	}
	return nil
}

func (m *JA4Matcher) Match(hello *tls.ClientHelloInfo) bool {
	if hello == nil {
		return false
	}

	ja4 := ja4FromClientHello(hello)
	if ja4 == "" {
		return false
	}

	if m.app != nil {
		var ip string
		// hello.Conn is nil on the QUIC path (crypto/tls builds the QUIC
		// server with a nil conn), so no IP and no handoff there.
		if hello.Conn != nil {
			if ap, ok := normalizeAddrPort(hello.Conn.RemoteAddr()); ok {
				ip = ap.Addr().String()
				if m.registry != nil {
					m.registry.fill(ap, ja4)
				}
			}
		}
		m.app.RecordJA4(ja4, ip)
	}

	if len(m.set) == 0 {
		return false
	}
	_, blocked := m.set[ja4]
	return blocked
}

// UnmarshalCaddyfile satisfies the Caddyfile interface. Config is JSON-only.
func (m *JA4Matcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

// Interface guards.
var (
	_ caddy.Provisioner          = (*JA4Matcher)(nil)
	_ caddyfile.Unmarshaler      = (*JA4Matcher)(nil)
	_ caddytls.ConnectionMatcher = (*JA4Matcher)(nil)
)
