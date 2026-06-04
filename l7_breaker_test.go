package apxstats

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// breakerApp builds a minimal StatsApp with the breaker config resolved
// directly (no Caddy lifecycle). Used to unit-test the evaluateL7PathBreaker
// state machine in isolation.
func breakerApp(threshold, windows int) *StatsApp {
	a := &StatsApp{ProxyServerIDValue: 42}
	a.cfg = ingestRuntime{
		l7PathBreakerThreshold: intDefault(threshold, L7PathBreakerThresholdDefault),
		l7PathBreakerWindows:   intDefault(windows, L7PathBreakerWindowsDefault),
	}
	return a
}

func TestEvaluateL7PathBreaker_LatchesAfterKConsecutiveWindows(t *testing.T) {
	a := breakerApp(100, 3)

	// First two over-threshold windows: streak builds but NOT latched yet.
	a.evaluateL7PathBreaker(150)
	require.False(t, a.l7PathAggregateOnly.Load(), "not latched after 1 window")
	require.Equal(t, 1, a.l7PathOverflowStreak)

	a.evaluateL7PathBreaker(150)
	require.False(t, a.l7PathAggregateOnly.Load(), "not latched after 2 windows")
	require.Equal(t, 2, a.l7PathOverflowStreak)

	// Third consecutive over-threshold window: latch.
	a.evaluateL7PathBreaker(150)
	require.True(t, a.l7PathAggregateOnly.Load(), "latched after the K-th (3rd) window")
	require.Equal(t, 3, a.l7PathOverflowStreak)
}

func TestEvaluateL7PathBreaker_LatchesExactlyAtThreshold(t *testing.T) {
	// overflow == threshold counts as over-threshold (>=).
	a := breakerApp(100, 1)
	a.evaluateL7PathBreaker(100)
	require.True(t, a.l7PathAggregateOnly.Load(), "overflow == threshold trips with windows=1")
}

func TestEvaluateL7PathBreaker_RecoversOnBelowThresholdWindow(t *testing.T) {
	a := breakerApp(100, 2)

	a.evaluateL7PathBreaker(150)
	a.evaluateL7PathBreaker(150)
	require.True(t, a.l7PathAggregateOnly.Load(), "latched after 2 windows")

	// A below-threshold window resets the streak AND clears the latch.
	a.evaluateL7PathBreaker(10)
	require.False(t, a.l7PathAggregateOnly.Load(), "recovered on below-threshold window")
	require.Equal(t, 0, a.l7PathOverflowStreak)
}

func TestEvaluateL7PathBreaker_SingleSpikeThenUnderDoesNotLatch(t *testing.T) {
	a := breakerApp(100, 3)

	a.evaluateL7PathBreaker(150) // spike
	require.Equal(t, 1, a.l7PathOverflowStreak)

	a.evaluateL7PathBreaker(10) // back under
	require.Equal(t, 0, a.l7PathOverflowStreak, "streak reset by under-threshold window")
	require.False(t, a.l7PathAggregateOnly.Load(), "single spike never latches")

	// Even a subsequent spike starts the streak over from 1.
	a.evaluateL7PathBreaker(150)
	require.Equal(t, 1, a.l7PathOverflowStreak)
	require.False(t, a.l7PathAggregateOnly.Load())
}

func TestEvaluateL7PathBreaker_DefaultThresholdResolution(t *testing.T) {
	// config 0 → default 50_000 threshold, default 3 windows.
	a := breakerApp(0, 0)
	require.Equal(t, L7PathBreakerThresholdDefault, a.cfg.l7PathBreakerThreshold)
	require.Equal(t, 50_000, a.cfg.l7PathBreakerThreshold)
	require.Equal(t, L7PathBreakerWindowsDefault, a.cfg.l7PathBreakerWindows)
	require.Equal(t, 3, a.cfg.l7PathBreakerWindows)

	// Just under the default never trips; at the default trips after K windows.
	for i := 0; i < 10; i++ {
		a.evaluateL7PathBreaker(49_999)
	}
	require.False(t, a.l7PathAggregateOnly.Load(), "below default threshold never latches")

	for i := 0; i < 3; i++ {
		a.evaluateL7PathBreaker(50_000)
	}
	require.True(t, a.l7PathAggregateOnly.Load(), "at default threshold latches after 3 windows")
}

// TestRecordL7Path_NoOpWhileLatched drives a fully configured app, forces the
// breaker latch, then confirms RecordL7Path records nothing into the recorder.
func TestRecordL7Path_NoOpWhileLatched(t *testing.T) {
	a := newTestApp(t, "http://example.invalid", "k", func(a *StatsApp) {
		a.Ingest.L7 = &L7Config{Enabled: true, TrackedVhosts: 64, PathsPerVhost: 16}
	})
	require.NotNil(t, a.l7Path)

	// Latch via the state machine: a low threshold + windows=1, one window.
	a.cfg.l7PathBreakerThreshold = 1
	a.cfg.l7PathBreakerWindows = 1
	a.evaluateL7PathBreaker(5)
	require.True(t, a.l7PathAggregateOnly.Load(), "breaker latched")

	// While latched, RecordL7Path is a no-op.
	for i := 0; i < 10; i++ {
		a.RecordL7Path(100, "/api/users", 2)
	}

	rows, _ := a.l7Path.drain(777)
	require.Empty(t, rows, "no rows recorded while breaker is latched")
}

// TestRecordL7Path_RecordsAfterRecovery confirms the latch gating is live:
// records before latch land, records during latch are dropped, records after
// recovery land again.
func TestRecordL7Path_RecordsAfterRecovery(t *testing.T) {
	a := newTestApp(t, "http://example.invalid", "k", func(a *StatsApp) {
		a.Ingest.L7 = &L7Config{Enabled: true, TrackedVhosts: 64, PathsPerVhost: 16}
	})
	a.cfg.l7PathBreakerThreshold = 1
	a.cfg.l7PathBreakerWindows = 1

	// Latch.
	a.evaluateL7PathBreaker(5)
	require.True(t, a.l7PathAggregateOnly.Load())
	a.RecordL7Path(100, "/dropped", 2)

	// Recover via a below-threshold window.
	a.evaluateL7PathBreaker(0)
	require.False(t, a.l7PathAggregateOnly.Load())
	a.RecordL7Path(100, "/kept", 2)

	rows, _ := a.l7Path.drain(777)
	m := make(map[string]uint64, len(rows))
	for _, r := range rows {
		m[r.Key.PathBucket] = r.Count
	}
	require.NotContains(t, m, "/dropped", "record while latched is dropped")
	require.Equal(t, uint64(1), m["/kept"], "record after recovery lands")
}
