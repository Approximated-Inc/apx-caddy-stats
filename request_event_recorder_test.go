package apxstats

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestEventRecorder_BelowThreshold_KeepsAllSampleRate1(t *testing.T) {
	r := newRequestEventRecorder(1000, 10, nil)
	const n = 5 // < threshold
	for i := 0; i < n; i++ {
		r.record(requestEventRow{VhostID: uint32(i)})
	}
	rows, overflow := r.drain()
	require.Len(t, rows, n)
	require.Zero(t, overflow)
	for _, row := range rows {
		require.Equal(t, uint16(1), row.SampleRate)
	}
}

func TestRequestEventRecorder_AboveThreshold_SamplesAndStamps(t *testing.T) {
	r := newRequestEventRecorder(10000, 10, nil)
	const n = 100
	for i := 0; i < n; i++ {
		r.record(requestEventRow{VhostID: uint32(i)})
	}
	rows, _ := r.drain()
	// Sampling engaged: meaningfully fewer than n kept.
	require.Less(t, len(rows), n)
	require.NotEmpty(t, rows)
	// Every kept row that was sampled carries SampleRate > 1. (The first
	// `threshold` rows are kept at SampleRate=1; beyond that, sampling
	// stamps n>1.) At least some rows must carry SampleRate > 1.
	sawSampled := false
	for _, row := range rows {
		require.GreaterOrEqual(t, row.SampleRate, uint16(1))
		if row.SampleRate > 1 {
			sawSampled = true
		}
	}
	require.True(t, sawSampled, "expected at least one sampled row with SampleRate>1")
}

func TestRequestEventRecorder_Cap_OverflowCounts(t *testing.T) {
	r := newRequestEventRecorder(5, 0, nil) // threshold<=0 -> keep every row
	for i := 0; i < 20; i++ {
		r.record(requestEventRow{VhostID: uint32(i)})
	}
	rows, overflow := r.drain()
	require.Len(t, rows, 5)
	require.Equal(t, uint64(15), overflow)
}

func TestRequestEventRecorder_DrainResetsWindow(t *testing.T) {
	r := newRequestEventRecorder(5, 0, nil)
	for i := 0; i < 20; i++ {
		r.record(requestEventRow{VhostID: uint32(i)})
	}
	_, overflow := r.drain()
	require.Equal(t, uint64(15), overflow)

	// Second drain: window reset -> empty + no overflow.
	rows, overflow := r.drain()
	require.Empty(t, rows)
	require.Zero(t, overflow)

	// Recording below threshold again yields SampleRate=1 (seen reset).
	r2 := newRequestEventRecorder(1000, 10, nil)
	for i := 0; i < 100; i++ {
		r2.record(requestEventRow{})
	}
	r2.drain() // exhaust window
	r2.record(requestEventRow{})
	rows, _ = r2.drain()
	require.Len(t, rows, 1)
	require.Equal(t, uint16(1), rows[0].SampleRate)
}

// --- memory-governor integration ---

func TestRequestEventRecorder_GovernorByteBudget_DropsAndCounts(t *testing.T) {
	// Exhaust the share budget externally: every row the sampler keeps
	// must fail tryReserve → dropped + counted in overflow, never appended.
	g := newMemGovernor(1_000_000, stubRSS(0), nil)
	require.True(t, g.tryReserve(int(g.shareBudget)))

	r := newRequestEventRecorder(1_000, 0, g)
	const n = 32
	for i := 0; i < n; i++ {
		r.record(requestEventRow{Path: "/p", UA: "ua"})
	}
	rows, overflow := r.drain()
	require.Empty(t, rows, "no row may buffer past the share budget")
	require.Positive(t, overflow, "budget-rejected rows must count as overflow")
	require.Equal(t, int64(g.shareBudget), g.bufferBytes.Load(),
		"rejected rows must not leak reservations")
}

func TestRequestEventRecorder_PressureDrivenSampling(t *testing.T) {
	// 90% of the share budget already reserved → pressure ≈ 0.9 → the
	// recorder must shed rows by sampling even though its configured
	// threshold (0) would never sample.
	g := newMemGovernor(1<<30, stubRSS(0), nil)
	require.True(t, g.tryReserve(int(float64(g.shareBudget)*0.9)))

	r := newRequestEventRecorder(100_000, 0, g)
	const n = 200
	for i := 0; i < n; i++ {
		r.record(requestEventRow{})
	}
	rows, overflow := r.drain()
	require.Zero(t, overflow, "plenty of byte budget remains — no hard drops expected")
	require.NotEmpty(t, rows)
	require.Less(t, len(rows), n/2, "pressure must shed a meaningful share of rows")
	for _, row := range rows {
		require.Greater(t, row.SampleRate, uint16(1),
			"pressure-sampled rows must stamp their factor so Phoenix can upscale")
	}
}

func TestRequestEventRecorder_NoPressure_NoSampling(t *testing.T) {
	// Low pressure: the governor must not perturb the existing semantics.
	g := newMemGovernor(1<<30, stubRSS(0), nil)
	r := newRequestEventRecorder(1_000, 0, g)
	const n = 50
	for i := 0; i < n; i++ {
		r.record(requestEventRow{Path: "/p"})
	}
	rows, overflow := r.drain()
	require.Len(t, rows, n)
	require.Zero(t, overflow)
	for _, row := range rows {
		require.Equal(t, uint16(1), row.SampleRate)
	}
}

func TestRequestEventRecorder_DrainReleasesGovernorBytes(t *testing.T) {
	g := newMemGovernor(1<<20, stubRSS(0), nil) // share ~419K
	r := newRequestEventRecorder(1_000, 0, g)
	row := requestEventRow{Path: "/some/path", UA: "agent", ClientIP: "203.0.113.9"}
	for i := 0; i < 100; i++ {
		r.record(row)
	}
	require.Positive(t, g.bufferBytes.Load(), "buffered rows must hold reservations")

	rows, _ := r.drain()
	require.NotEmpty(t, rows)
	require.Zero(t, g.bufferBytes.Load(), "drain must release every byte it reserved")
	require.True(t, g.tryReserve(int(g.shareBudget)), "the full budget is usable next window")
}

func TestRequestEventRecorderV2_ServedUnsampled(t *testing.T) {
	// mode_v2: served rows are never threshold-sampled, even far past what
	// a blocked threshold would trigger. All kept, SampleRate=1, up to cap.
	r := newRequestEventRecorderV2(100000, 10, nil)
	const n = 500
	for i := 0; i < n; i++ {
		r.record(requestEventRow{Disposition: dispServed, VhostID: uint32(i)})
	}
	rows, overflow := r.drain()
	require.Zero(t, overflow)
	require.Len(t, rows, n, "served rows must not be sampled in v2")
	for _, row := range rows {
		require.Equal(t, uint16(1), row.SampleRate)
	}
}

func TestRequestEventRecorderV2_NonServedSampledByBlockedThreshold(t *testing.T) {
	// mode_v2: blocked/challenge rows use their OWN threshold and sample
	// above it, stamping SampleRate>1.
	r := newRequestEventRecorderV2(100000, 10, nil)
	const n = 200
	for i := 0; i < n; i++ {
		r.record(requestEventRow{Disposition: dispWafBlocked})
	}
	rows, _ := r.drain()
	require.Less(t, len(rows), n, "non-served rows sample above the blocked threshold")
	require.NotEmpty(t, rows)
	sawSampled := false
	for _, row := range rows {
		require.GreaterOrEqual(t, row.SampleRate, uint16(1))
		if row.SampleRate > 1 {
			sawSampled = true
		}
	}
	require.True(t, sawSampled, "expected at least one blocked row with SampleRate>1")
}

func TestRequestEventRecorderV2_ServedAndBlockedIndependent(t *testing.T) {
	// The two streams keep separate seen counters: a flood of blocked rows
	// must not cause served rows to be sampled.
	r := newRequestEventRecorderV2(100000, 5, nil)
	for i := 0; i < 100; i++ {
		r.record(requestEventRow{Disposition: dispWafBlocked})
	}
	for i := 0; i < 100; i++ {
		r.record(requestEventRow{Disposition: dispServed})
	}
	rows, _ := r.drain()
	served := 0
	for _, row := range rows {
		if row.Disposition == dispServed {
			served++
			require.Equal(t, uint16(1), row.SampleRate)
		}
	}
	require.Equal(t, 100, served, "served stream unaffected by blocked flood")
}

func TestRequestEventRecorder_Race(t *testing.T) {
	r := newRequestEventRecorder(100000, 10, nil)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				r.record(requestEventRow{VhostID: uint32(g)})
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			r.drain()
		}
	}()
	wg.Wait()
	r.drain()
}
