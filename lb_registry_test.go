package apxstats

import (
	"testing"
	"time"
)

func withLBClock(t *testing.T, at *time.Time) {
	t.Helper()
	orig := lbNow
	lbNow = func() time.Time { return *at }
	t.Cleanup(func() { lbNow = orig; lbReset() })
	lbReset()
}

func TestLBScoreUnknownUpstream(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	if score, known := lbScore("10.0.0.1:443"); known || score != 0 {
		t.Fatalf("unknown upstream: got (%v, %v), want (0, false)", score, known)
	}
}

func TestLBRecordThenScore(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("10.0.0.1:443", 100*time.Millisecond)
	score, known := lbScore("10.0.0.1:443")
	if !known {
		t.Fatal("want known after lbRecord")
	}
	if score != float64(100*time.Millisecond) {
		t.Fatalf("first sample should seed the EWMA exactly: got %v", score)
	}
}

func TestLBRecordFoldsWithAlpha(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("a:1", 100*time.Millisecond)
	lbRecord("a:1", 200*time.Millisecond)

	want := lbAlpha*float64(200*time.Millisecond) + (1-lbAlpha)*float64(100*time.Millisecond)
	score, _ := lbScore("a:1")
	if score != want {
		t.Fatalf("got %v, want %v", score, want)
	}
}

func TestLBIdleScoreDecaysTowardOptimistic(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("a:1", 100*time.Millisecond)
	clock = clock.Add(lbDecayHalfLife)

	score, _ := lbScore("a:1")
	want := float64(100*time.Millisecond) / 2
	if score < want*0.99 || score > want*1.01 {
		t.Fatalf("after one half-life got %v, want about %v", score, want)
	}
}

func TestLBEvictDropsStaleEntries(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("a:1", 100*time.Millisecond)
	lbRecord("b:1", 100*time.Millisecond)
	clock = clock.Add(lbEvictAfter + time.Second)
	// Touch only b:1 so it is fresh at eviction time. An lbEvict that wiped
	// the whole map would still drop a:1 but must not pass this test.
	lbRecord("b:1", 100*time.Millisecond)
	lbEvict()

	if _, known := lbScore("a:1"); known {
		t.Fatal("stale entry should have been evicted")
	}
	if _, known := lbScore("b:1"); !known {
		t.Fatal("recently touched entry must survive eviction")
	}
}

func TestLBRecordIgnoresNonPositiveAndEmpty(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("", 100*time.Millisecond)
	lbRecord("a:1", 0)
	lbRecord("b:1", -time.Millisecond)

	if _, known := lbScore(""); known {
		t.Fatal("empty dial must not create an entry")
	}
	if _, known := lbScore("a:1"); known {
		t.Fatal("zero duration must not create an entry")
	}
	if _, known := lbScore("b:1"); known {
		t.Fatal("negative duration must not create an entry")
	}
}

// A regression test for a bug where lbRecord folded new samples into the
// *undecayed* stored EWMA, so decay only ever showed up in lbScore's read
// path, not in what got written back. That let one bad sample (e.g. a
// timeout) exile an upstream for ~20 recovery cycles instead of the single
// good sample decay is supposed to allow once the exile itself has decayed
// away.
func TestLBRecordFoldsAgainstDecayedStoredValue(t *testing.T) {
	clock := time.Unix(0, 0)
	withLBClock(t, &clock)

	lbRecord("a:1", 6*time.Second)
	clock = clock.Add(10 * lbDecayHalfLife)
	lbRecord("a:1", 50*time.Millisecond)

	score, _ := lbScore("a:1")
	if score >= float64(100*time.Millisecond) {
		t.Fatalf("stale exile should have decayed away before folding in the new sample: got %v (>= 100ms)", score)
	}
}
