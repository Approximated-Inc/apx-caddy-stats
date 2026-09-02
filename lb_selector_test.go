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

// lbNoInFlight is the zero-value in-flight accessor for tests that aren't
// exercising the in-flight scaling term itself.
func lbNoInFlight(*reverseproxy.Upstream) int { return 0 }

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

	got := lbSelectLowest(p, available, lbNoInFlight)
	if got == nil || got.Dial != "alive:443" {
		t.Fatalf("got %v, want alive:443 — an unhealthy upstream must never be selected however fast", got)
	}
}

func TestLBSelectReturnsNilWhenNoneAvailable(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	p := lbPool("a:443", "b:443")

	got := lbSelectLowest(p, func(*reverseproxy.Upstream) bool { return false }, lbNoInFlight)
	if got != nil {
		t.Fatalf("got %v, want nil when every upstream is unavailable", got)
	}
}

// Caddy tracks in-flight request count through the unexported countRequest
// (hosts.go) — only the read side, NumRequests, is exported — so, like
// availability above, a test in this package cannot put a real upstream
// mid-request and must inject the accessor instead.
//
// loaded:443 is faster at rest (20ms) than baseline:443 (50ms), but with 3
// requests already in flight its score is 20ms*(3+1) = 80ms, worse than
// baseline's resting score of 50ms*(0+1) = 50ms. The in-flight term must be
// able to flip the ranking, or it isn't doing anything.
func TestLBSelectInFlightPenalizesLoadedUpstream(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("loaded:443", 20*time.Millisecond)
	lbRecord("baseline:443", 50*time.Millisecond)

	p := lbPool("loaded:443", "baseline:443")
	inflight := map[string]int{"loaded:443": 3}

	got := lbSelectLowest(p, func(*reverseproxy.Upstream) bool { return true },
		func(u *reverseproxy.Upstream) int { return inflight[u.Dial] })
	if got == nil || got.Dial != "baseline:443" {
		t.Fatalf("got %v, want baseline:443 — 3 in-flight requests on the faster upstream (score 80) should lose to the slower upstream at rest (score 50)", got)
	}
}

// The mirror of the above: with only 1 in flight, loaded:443's score is
// 20ms*(1+1) = 40ms, still under baseline's resting 50ms, so it must keep
// winning. Checking both directions matters — a test that only showed the
// loaded upstream losing would also pass if the term were wildly
// overweighted (e.g. any in-flight request at all disqualifies).
func TestLBSelectLowInFlightStillWins(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("loaded:443", 20*time.Millisecond)
	lbRecord("baseline:443", 50*time.Millisecond)

	p := lbPool("loaded:443", "baseline:443")
	inflight := map[string]int{"loaded:443": 1}

	got := lbSelectLowest(p, func(*reverseproxy.Upstream) bool { return true },
		func(u *reverseproxy.Upstream) int { return inflight[u.Dial] })
	if got == nil || got.Dial != "loaded:443" {
		t.Fatalf("got %v, want loaded:443 — 1 in-flight request (score 40) should still beat the slower upstream at rest (score 50)", got)
	}
}
