package apxstats

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
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

// --- concurrency ---
//
// The registry has two genuinely concurrent callers in production: the HTTP
// server's accept goroutine (put, via StatsHandler.ja4ConnContext) and the TLS
// handshake goroutine (fill, via JA4Matcher.Match). These run -race.

// sizes reports the registry's map and list lengths under its own lock.
// Test-only invariant probe: the two must never disagree.
func (r *ja4Registry) sizes() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m), r.ll.Len()
}

func TestJA4Registry_concurrentPutFillDistinctKeys(t *testing.T) {
	// Every goroutine owns its own connection, as in production. Under a cap
	// well above the goroutine count nothing is evicted, so EVERY handoff must
	// succeed — a weaker "didn't crash" assertion would pass against a
	// registry that silently lost entries.
	const goroutines = 64
	r := newJA4Registry(4096)

	var wg sync.WaitGroup
	errs := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(1024+i))
			want := fmt.Sprintf("t13d1516h2_%012d_ffffffffffff", i)
			h := &ja4Holder{}
			r.put(key, h)
			if !r.fill(key, want) {
				errs[i] = "fill found no holder"
				return
			}
			if got := h.get(); got != want {
				errs[i] = fmt.Sprintf("holder = %q, want %q", got, want)
			}
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		if e != "" {
			t.Errorf("goroutine %d: %s", i, e)
		}
	}
	if m, l := r.sizes(); m != 0 || l != 0 {
		t.Errorf("registry not drained: map=%d list=%d, want 0/0", m, l)
	}
}

func TestJA4Registry_concurrentPutFillSharedKeys(t *testing.T) {
	// Adversarial: many goroutines hammer a handful of shared keys, so puts
	// race puts and fills race both. Per put()'s documented limitation a
	// handoff may be redirected, so we cannot assert every fill succeeds —
	// but the map/list must stay consistent, and no holder may ever surface a
	// value nobody wrote.
	const goroutines = 64
	const keys = 4
	r := newJA4Registry(64)

	valid := make(map[string]struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		valid[fmt.Sprintf("t13d1516h2_%012d_ffffffffffff", i)] = struct{}{}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad []string
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(1024+i%keys))
			h := &ja4Holder{}
			r.put(key, h)
			r.fill(key, fmt.Sprintf("t13d1516h2_%012d_ffffffffffff", i))
			got := h.get()
			if got == "" {
				return // redirected handoff — documented, allowed
			}
			if _, ok := valid[got]; !ok {
				mu.Lock()
				bad = append(bad, got)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if len(bad) > 0 {
		t.Errorf("holders surfaced values nobody wrote: %v", bad)
	}
	if m, l := r.sizes(); m != l {
		t.Errorf("map/list disagree after concurrent access: map=%d list=%d", m, l)
	}
}

func TestJA4Registry_concurrentPutAtCap(t *testing.T) {
	// Concurrent inserts past the cap drive the eviction path — the one place
	// put() mutates both the list and the map. The two must stay in lockstep
	// and the registry must never exceed its bound.
	const goroutines = 128
	const max = 8
	r := newJA4Registry(max)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.put(netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(1024+i)), &ja4Holder{})
		}(i)
	}
	wg.Wait()

	m, l := r.sizes()
	if m != l {
		t.Errorf("map/list disagree: map=%d list=%d", m, l)
	}
	if l > max {
		t.Errorf("registry exceeded its cap: list=%d, max=%d", l, max)
	}
}

func TestJA4Holder_concurrentSetOnceAndGet(t *testing.T) {
	// A HelloRetryRequest can deliver a second ClientHello while a request is
	// already reading, so writers race writers AND readers. Exactly one value
	// must win, and readers must never see anything else.
	const writers = 32
	const readers = 32
	h := &ja4Holder{}

	valid := make(map[string]struct{}, writers)
	for i := 0; i < writers; i++ {
		valid[fmt.Sprintf("t13d1516h2_%012d_ffffffffffff", i)] = struct{}{}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad []string

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			h.setOnce(fmt.Sprintf("t13d1516h2_%012d_ffffffffffff", i))
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 200; j++ {
				got := h.get()
				if got == "" {
					continue
				}
				if _, ok := valid[got]; !ok {
					mu.Lock()
					bad = append(bad, got)
					mu.Unlock()
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(bad) > 0 {
		t.Errorf("readers saw values nobody wrote: %v", bad)
	}
	final := h.get()
	if _, ok := valid[final]; !ok {
		t.Fatalf("final value %q is not one of the written values", final)
	}
	// First write wins is a stability property, not just a one-shot one.
	for i := 0; i < 100; i++ {
		if got := h.get(); got != final {
			t.Fatalf("holder value changed after settling: %q then %q", final, got)
		}
	}
	h.setOnce("t13d1516h2_999999999999_ffffffffffff")
	if got := h.get(); got != final {
		t.Errorf("a late setOnce overwrote the settled value: %q, want %q", got, final)
	}
}
