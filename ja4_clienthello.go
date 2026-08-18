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
// LegacyVersion is deliberately left zero: ja4Version consults it only when
// SupportedVersions carries no non-GREASE entry, and crypto/tls always
// populates SupportedVersions (falling back to supportedVersionsFromMax when
// the extension is absent). The tls12_alpn_h2 FoxIO vector is the regression
// test for that omission — it has no supported_versions extension yet still
// fingerprints as "t12d", proving the stdlib fallback fires.
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

// ja4Transport returns the JA4_a leading character. quic-go populates
// hello.Conn on the QUIC path, so LocalAddr().Network() distinguishes the
// transport; extension 0x0039 (quic_transport_parameters) corroborates and
// covers the case where Conn is absent.
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
