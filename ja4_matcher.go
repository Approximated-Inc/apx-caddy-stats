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
//
// FORWARD-LOOKING CONSTRAINT — not a problem today. Above 30 connection
// policies on one server, caddytls builds an indexedBySNI fast path
// (connpolicy.go), and an SNI-bearing handshake then only considers policies
// carrying a MatchServerName matcher — a policy without one stops being
// reached at all. Approximated generates ONE connection-policy list per
// server (two entries once the catch-all lands), so that path is unreachable.
// If the list ever grows past 30, this matcher must ride the SNI-matched
// policies instead of sitting in a policy of its own.
type JA4Matcher struct {
	// Blocklist is the set of JA4 strings that match. Empty means the matcher
	// never matches — record-only mode.
	Blocklist []string `json:"blocklist,omitempty"`

	// Record controls whether Match writes the fingerprint to the app's
	// fingerprint maps. Set it FALSE on clusters where the layer-4
	// FingerprintHandler is already recording: both paths see the same
	// handshake and fpIpMap is keyed (ja4, ip) on both, so leaving them both
	// on doubles connection_count and burns two fpMap keys per fingerprint
	// against one shared cap.
	//
	// nil (absent from config) means RECORD. Defaulting to off would make a
	// cluster that omits the field silently stop producing the very rows this
	// module exists for; double counting is the cheaper failure.
	//
	// This never gates the handoff to the request context — that happens on
	// every handshake regardless, because the L4 recorder cannot supply it.
	Record *bool `json:"record,omitempty"`

	set      map[string]struct{}
	app      *StatsApp
	registry *ja4Registry
	logger   *zap.Logger
}

// ja4MatcherModuleKey is this matcher's key within a connection policy's
// `match` object — the last segment of the module ID, which is how
// caddy.ModuleMap names entries in the tls.handshake_match namespace.
const ja4MatcherModuleKey = "apx_ja4"

func (*JA4Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID("tls.handshake_match." + ja4MatcherModuleKey),
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
			zap.Bool("record_only", len(m.set) == 0),
			zap.Bool("record", m.recordEnabled()))
	}
	return nil
}

// recordEnabled reports whether Match should record into the fingerprint maps.
// See the Record field: absent config means yes.
func (m *JA4Matcher) recordEnabled() bool {
	return m.Record == nil || *m.Record
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

	var ip string
	// hello.Conn is populated on BOTH transports: crypto/tls sets it for TLS
	// over TCP, and quic-go injects a stub conn carrying the real UDP
	// addresses before delegating to GetConfigForClient (see ja4Transport).
	// A nil Conn is therefore an unusual embedding, not the QUIC path.
	if hello.Conn != nil {
		if ap, ok := normalizeAddrPort(hello.Conn.RemoteAddr()); ok {
			ip = ap.Addr().String()
			// The handoff runs even when Record is off: the L4 recorder
			// records but cannot reach the HTTP request context, so this is
			// the only path that puts a fingerprint on the request.
			if m.registry != nil {
				m.registry.fill(ap, ja4)
			}
		}
	}
	if m.app != nil && m.recordEnabled() {
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
