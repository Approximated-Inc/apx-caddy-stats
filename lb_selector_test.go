package apxstats

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func lbPool(dials ...string) reverseproxy.UpstreamPool {
	p := make(reverseproxy.UpstreamPool, 0, len(dials))
	for _, d := range dials {
		u := &reverseproxy.Upstream{Dial: d}
		// Provisioning normally fills this; without a Host the upstream
		// panics on NumRequests.
		u.Host = new(reverseproxy.Host)
		p = append(p, u)
	}
	return p
}

func TestLBSelectPrefersLowerLatency(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("near:443", 20*time.Millisecond)
	lbRecord("far:443", 250*time.Millisecond)

	got := LatencySelection{}.Select(lbPool("far:443", "near:443"), nil, nil)
	if got == nil || got.Dial != "near:443" {
		t.Fatalf("got %v, want near:443", got)
	}
}

func TestLBSelectColdPoolFallsBackToConfigOrder(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	got := LatencySelection{}.Select(lbPool("primary:443", "secondary:443"), nil, nil)
	if got == nil || got.Dial != "primary:443" {
		t.Fatalf("cold pool should pick the configured primary, got %v", got)
	}
}

func TestLBSelectReturnsLeastBadWhenAllSlow(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("a:443", 9*time.Second)
	lbRecord("b:443", 10*time.Second)

	got := LatencySelection{}.Select(lbPool("a:443", "b:443"), nil, nil)
	if got == nil {
		t.Fatal("must never return nil while an upstream is available")
	}
	if got.Dial != "a:443" {
		t.Fatalf("got %v, want the least-bad upstream a:443", got)
	}
}

// Caddy marks an upstream unhealthy through unexported state (setHealthy,
// countFail and the unhealthy atomic are all package-private), so a test in
// another package cannot simulate it. Availability is injected instead.
func TestLBSelectSkipsUnavailable(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("dead:443", 1*time.Millisecond)
	lbRecord("alive:443", 200*time.Millisecond)

	p := lbPool("dead:443", "alive:443")
	available := func(u *reverseproxy.Upstream) bool { return u.Dial != "dead:443" }

	got := lbSelectLowest(p, available)
	if got == nil || got.Dial != "alive:443" {
		t.Fatalf("got %v, want alive:443 — an unhealthy upstream must never be selected however fast", got)
	}
}

func TestLBSelectReturnsNilWhenNoneAvailable(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	p := lbPool("a:443", "b:443")

	got := lbSelectLowest(p, func(*reverseproxy.Upstream) bool { return false })
	if got != nil {
		t.Fatalf("got %v, want nil when every upstream is unavailable", got)
	}
}
