package apxstats

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mholt/caddy-l4/modules/l4tls"
)

// ja4ViaStdlibHandshake writes a raw ClientHello record to a real crypto/tls
// server and returns the JA4 computed from the *tls.ClientHelloInfo the stdlib
// builds. GetConfigForClient fires before version negotiation, so this works
// even for hellos the handshake would later reject.
func ja4ViaStdlibHandshake(t *testing.T, record []byte) (string, error) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	var (
		mu   sync.Mutex
		ja4  string
		seen = make(chan struct{})
	)

	cfg := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			ja4 = ja4FromClientHello(hello)
			mu.Unlock()
			close(seen)
			return nil, errors.New("stop handshake: fingerprint captured")
		},
	}

	go func() { _ = tls.Server(server, cfg).Handshake() }()
	go func() { _, _ = client.Write(record) }()

	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		return "", errors.New("GetConfigForClient never fired")
	}

	mu.Lock()
	defer mu.Unlock()
	return ja4, nil
}

// wantMinFoxIOVectors is the number of vendored FoxIO vectors carrying an
// ExpectedJA4 at the time this gate was written. The parity test must never
// assert fewer than this.
const wantMinFoxIOVectors = 6

func TestJA4FromClientHello_matchesFoxIOVectors(t *testing.T) {
	if len(l4tls.JAVectors) == 0 {
		t.Fatal("no FoxIO vectors vendored — the parity test is meaningless")
	}

	checked := 0
	for _, v := range l4tls.JAVectors {
		if v.ExpectedJA4 == "" {
			continue
		}
		checked++
		t.Run(v.Name, func(t *testing.T) {
			hello, err := hex.DecodeString(v.ClientHello)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			// Frame the handshake message as a TLS record.
			rec := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)

			got, err := ja4ViaStdlibHandshake(t, rec)
			if err != nil {
				t.Fatalf("capture failed: %v", err)
			}
			if got != v.ExpectedJA4 {
				t.Errorf("JA4 mismatch\n got: %q\nwant: %q", got, v.ExpectedJA4)
			}
		})
	}

	// A bare `checked == 0` guard would let the gate silently shrink from 6
	// vectors to 5 — e.g. if one lost its ExpectedJA4 — and stay green. Assert
	// an explicit floor instead. Growth is fine (more coverage still clears the
	// floor); any shrink fails loudly, which is what the "do not relax the
	// corpus" constraint actually requires.
	if checked < wantMinFoxIOVectors {
		t.Fatalf("parity gate shrank: asserted %d vectors, want at least %d", checked, wantMinFoxIOVectors)
	}
}

func TestJA4FromClientHello_nilIsEmpty(t *testing.T) {
	if got := ja4FromClientHello(nil); got != "" {
		t.Errorf("ja4FromClientHello(nil) = %q, want \"\"", got)
	}
}

// TestJA4Transport covers the JA4_a leading character without needing a QUIC
// stack. In production the LocalAddr().Network() branch is the primary signal —
// quic-go injects a stub conn carrying the real *net.UDPAddr before caddytls's
// GetConfigForClient runs (see ja4Transport's comment) — and the ext-0x0039
// branch corroborates it. Both are exercised here; both yield 'q'.
func TestJA4Transport(t *testing.T) {
	udpConn := &ja4TestConn{
		local:  &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443},
		remote: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 52000},
	}

	tests := []struct {
		name  string
		hello *tls.ClientHelloInfo
		want  byte
	}{
		{
			name:  "udp LocalAddr yields q with no quic extension",
			hello: &tls.ClientHelloInfo{Conn: udpConn, Extensions: []uint16{0x0000, 0x002b}},
			want:  'q',
		},
		{
			name:  "udp LocalAddr and the quic extension agree on q",
			hello: &tls.ClientHelloInfo{Conn: udpConn, Extensions: []uint16{0x0039}},
			want:  'q',
		},
		{
			name: "tcp LocalAddr yields t",
			hello: &tls.ClientHelloInfo{
				Conn:       newJA4TestConn("203.0.113.9:52000"),
				Extensions: []uint16{0x0000, 0x002b},
			},
			want: 't',
		},
		{
			name:  "quic_transport_parameters ext yields q",
			hello: &tls.ClientHelloInfo{Extensions: []uint16{0x0039}},
			want:  'q',
		},
		{
			name:  "quic ext among others still yields q",
			hello: &tls.ClientHelloInfo{Extensions: []uint16{0x0000, 0x000a, 0x0039, 0x002b}},
			want:  'q',
		},
		{
			name:  "plain TCP hello yields t",
			hello: &tls.ClientHelloInfo{Extensions: []uint16{0x0000, 0x000a, 0x002b}},
			want:  't',
		},
		{
			name:  "no extensions and nil Conn yields t",
			hello: &tls.ClientHelloInfo{},
			want:  't',
		},
		{
			name:  "draft QUIC ext 0xffa5 is not recognized, yields t",
			hello: &tls.ClientHelloInfo{Extensions: []uint16{0xffa5}},
			want:  't',
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ja4Transport(tc.hello); got != tc.want {
				t.Errorf("ja4Transport() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestJA4FromClientHello_legacyVersionDivergence pins the one known parity gap
// between this path and the L4 path.
//
// *tls.ClientHelloInfo does not expose legacy_version, so when a hello carries
// no supported_versions extension the stdlib path can only see whatever
// supportedVersionsFromMax(legacy) synthesized — which is EMPTY for legacy
// < 0x0301. The L4 path passes the real legacy version through as
// JA4Input.LegacyVersion and so can still emit "s3"/"s2".
//
// The stdlib side is measured through a real crypto/tls handshake. The L4 side
// is computed as l4tls.JA4 with LegacyVersion set, which is exactly the
// JA4Input l4tls's own ja4InputFromCHI builds for a hello with no
// supported_versions extension (SupportedVersions empty, LegacyVersion = the
// wire value).
//
// This test exists so the gap cannot silently widen: if a future change makes
// an in-range version diverge, the "agree" rows fail.
func TestJA4FromClientHello_legacyVersionDivergence(t *testing.T) {
	// tls12_alpn_h2 is the only vector with no supported_versions extension,
	// so patching its legacy_version actually changes what the stdlib derives.
	var vec l4tls.JAVector
	for _, v := range l4tls.JAVectors {
		if v.Name == "tls12_alpn_h2" {
			vec = v
		}
	}
	if vec.ClientHello == "" {
		t.Fatal("tls12_alpn_h2 vector not found — divergence test cannot run")
	}
	base, err := hex.DecodeString(vec.ClientHello)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	if containsUint16(extensionsOf(t, base), 0x002b) {
		t.Fatal("tls12_alpn_h2 unexpectedly has supported_versions — test premise broken")
	}

	tests := []struct {
		name       string
		legacy     uint16
		wantStdlib string // JA4_a version code via crypto/tls
		wantL4     string // JA4_a version code via LegacyVersion passthrough
	}{
		{"TLS1.2 agrees", 0x0303, "12", "12"},
		{"TLS1.0 agrees at the lower boundary", 0x0301, "10", "10"},
		{"SSLv3 diverges", 0x0300, "00", "s3"},
		{"SSLv2 diverges", 0x0002, "00", "s2"},
		{"above TLS1.3 diverges", 0x0305, "13", "00"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hello := append([]byte(nil), base...)
			hello[4] = byte(tc.legacy >> 8) // legacy_version follows the 4-byte
			hello[5] = byte(tc.legacy)      // handshake header
			rec := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)

			gotJA4, err := ja4ViaStdlibHandshake(t, rec)
			if err != nil {
				t.Fatalf("capture failed: %v", err)
			}
			if got := versionCode(t, gotJA4); got != tc.wantStdlib {
				t.Errorf("stdlib path version = %q, want %q (full JA4 %q)", got, tc.wantStdlib, gotJA4)
			}

			l4JA4 := l4tls.JA4(l4tls.JA4Input{LegacyVersion: tc.legacy})
			if got := versionCode(t, l4JA4); got != tc.wantL4 {
				t.Errorf("L4 path version = %q, want %q (full JA4 %q)", got, tc.wantL4, l4JA4)
			}

			diverges := tc.wantStdlib != tc.wantL4
			if !diverges && versionCode(t, gotJA4) != versionCode(t, l4JA4) {
				t.Errorf("in-range version %#04x must agree across paths, got stdlib=%q l4=%q",
					tc.legacy, versionCode(t, gotJA4), versionCode(t, l4JA4))
			}
		})
	}
}

// versionCode returns the 2-char JA4_a version field (chars 1-2 of the string).
func versionCode(t *testing.T, ja4 string) string {
	t.Helper()
	if len(ja4) < 3 {
		t.Fatalf("JA4 %q too short to carry a version code", ja4)
	}
	return ja4[1:3]
}

// extensionsOf returns the extension IDs the stdlib parses out of a raw
// ClientHello handshake message, used to verify a test's premise.
func extensionsOf(t *testing.T, hello []byte) []uint16 {
	t.Helper()
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	var (
		mu   sync.Mutex
		exts []uint16
		seen = make(chan struct{})
	)
	cfg := &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			exts = append([]uint16(nil), h.Extensions...)
			mu.Unlock()
			close(seen)
			return nil, errors.New("stop handshake")
		},
	}
	go func() { _ = tls.Server(server, cfg).Handshake() }()
	go func() { _, _ = client.Write(rec) }()

	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("GetConfigForClient never fired")
	}
	mu.Lock()
	defer mu.Unlock()
	return exts
}
