package apxstats

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestNormalizeAddrPort_unmapsV4MappedV6(t *testing.T) {
	// A v4-mapped address can stringify differently on the two sides of a
	// PROXY v2 round-trip. Both sides must key on the unmapped form or the
	// handoff silently misses. This is the PR #127 bug class.
	mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.9"), Port: 4433}
	plain := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4433}

	gotMapped, ok1 := normalizeAddrPort(mapped)
	gotPlain, ok2 := normalizeAddrPort(plain)

	if !ok1 || !ok2 {
		t.Fatalf("normalize failed: mapped=%v plain=%v", ok1, ok2)
	}
	if gotMapped != gotPlain {
		t.Errorf("v4-mapped and plain disagree: %v vs %v", gotMapped, gotPlain)
	}
}

func TestJA4Registry_fillRemovesEntry(t *testing.T) {
	r := newJA4Registry(8)
	key := netip.MustParseAddrPort("203.0.113.9:4433")
	h := &ja4Holder{}
	r.put(key, h)

	if !r.fill(key, "t13d1516h2_aaaa_bbbb") {
		t.Fatal("fill returned false for a registered key")
	}
	if got := h.get(); got != "t13d1516h2_aaaa_bbbb" {
		t.Errorf("holder = %q, want the filled value", got)
	}
	if r.fill(key, "second") {
		t.Error("fill succeeded twice — the entry must be removed on fill")
	}
}

func TestJA4Holder_firstWriteWins(t *testing.T) {
	// A HelloRetryRequest exchange delivers a second, legitimately different
	// ClientHello. One connection must yield one fingerprint, and we cannot
	// rely on tls.ClientHelloInfo.HelloRetryRequest existing in the builder
	// toolchain, so the holder itself enforces this.
	h := &ja4Holder{}
	h.setOnce("first")
	h.setOnce("second")

	if got := h.get(); got != "first" {
		t.Errorf("holder = %q, want \"first\"", got)
	}
}

func TestJA4Registry_evictsOldestAtCap(t *testing.T) {
	r := newJA4Registry(2)
	k1 := netip.MustParseAddrPort("203.0.113.1:1")
	k2 := netip.MustParseAddrPort("203.0.113.2:2")
	k3 := netip.MustParseAddrPort("203.0.113.3:3")
	r.put(k1, &ja4Holder{})
	r.put(k2, &ja4Holder{})
	r.put(k3, &ja4Holder{})

	if r.fill(k1, "x") {
		t.Error("oldest entry was not evicted at cap")
	}
	if !r.fill(k3, "x") {
		t.Error("newest entry should still be present")
	}
}

func TestJA4FromContext_absentIsEmpty(t *testing.T) {
	if got := ja4FromContext(context.Background()); got != "" {
		t.Errorf("ja4FromContext(empty) = %q, want \"\"", got)
	}
}
