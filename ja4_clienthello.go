package apxstats

import (
	"crypto/tls"

	"github.com/mholt/caddy-l4/modules/l4tls"
)

// ja4FromClientHello computes JA4 from a ClientHello as delivered by
// crypto/tls. Extensions, CipherSuites, SignatureSchemes and SupportedProtos
// are raw wire order with GREASE retained (Go >= 1.24), which is the same input
// shape l4tls's own parser produces — so this yields a byte-identical string to
// the L4 path for the same handshake. That equivalence is asserted against the
// FoxIO corpus in ja4_clienthello_test.go.
//
// LegacyVersion is left zero because *tls.ClientHelloInfo does not expose the
// ClientHello's legacy_version at all — irreducible information loss in the
// stdlib API, not a mapping choice. When the supported_versions extension is
// absent, crypto/tls synthesizes SupportedVersions via
// supportedVersionsFromMax(legacy) (handshake_server.go clientHelloInfo), which
// keeps only {0x0304,0x0303,0x0302,0x0301} entries <= legacy. So
// SupportedVersions is populated for legacy >= 0x0301 and comes back EMPTY
// below it.
//
// That leaves a bounded parity gap against the L4 path, which does carry
// LegacyVersion. For a hello with no supported_versions extension:
//
//	legacy 0x0300 (SSLv3): L4 "s3" vs here "00"
//	legacy 0x0002 (SSLv2): L4 "s2" vs here "00"
//	legacy  > 0x0304:      L4 "00" vs here "13"
//
// The 0x0301–0x0304 range — every ClientHello that can actually complete a
// handshake — agrees exactly, and Go rejects the divergent ones right after
// GetConfigForClient returns, so JA4_a codes "s3"/"s2" are unreachable here.
// Pinned by TestJA4FromClientHello_legacyVersionDivergence; the tls12_alpn_h2
// FoxIO vector covers the in-range fallback (no supported_versions ext, still
// fingerprints "t12d").
func ja4FromClientHello(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}
	return l4tls.JA4(l4tls.JA4Input{
		SupportedVersions: hello.SupportedVersions,
		CipherSuites:      hello.CipherSuites,
		Extensions:        hello.Extensions,
		SignatureAlgos:    sigSchemesToUint16(hello.SignatureSchemes),
		ALPNs:             hello.SupportedProtos,
		SNIPresent:        containsUint16(hello.Extensions, 0x0000),
		Transport:         ja4Transport(hello),
	})
}

func sigSchemesToUint16(in []tls.SignatureScheme) []uint16 {
	if len(in) == 0 {
		return nil
	}
	out := make([]uint16, len(in))
	for i, s := range in {
		out[i] = uint16(s)
	}
	return out
}

func containsUint16(haystack []uint16, needle uint16) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// ja4Transport returns the JA4_a leading character.
//
// Extension 0x0039 (quic_transport_parameters, RFC 9001) is the branch that
// actually fires on the QUIC path: crypto/tls builds a QUIC server with
// Server(nil, cfg) (quic.go QUICServer) and then sets Conn: c.conn, so
// hello.Conn is NIL under QUIC and the LocalAddr().Network() check never runs
// there. That check is kept only as a corroborating fallback for transports
// that do supply a Conn — do not mistake it for the primary QUIC signal.
//
// Two known limits, both bounded:
//   - Draft QUIC used extension 0xffa5 rather than 0x0039; such a hello is
//     classified 't'. Only pre-RFC-9001 clients are affected.
//   - A TCP hello that carries 0x0039 yields "q…" here while the L4 path always
//     yields "t…" (it never sets Transport). RFC 9001 §8.2 forbids that
//     extension outside QUIC, so this is a spec violation by the client, but it
//     is a real second parity gap alongside the LegacyVersion one above.
func ja4Transport(hello *tls.ClientHelloInfo) byte {
	if hello.Conn != nil {
		if la := hello.Conn.LocalAddr(); la != nil {
			switch la.Network() {
			case "udp", "udp4", "udp6":
				return 'q'
			}
		}
	}
	if containsUint16(hello.Extensions, 0x0039) {
		return 'q'
	}
	return 't'
}
