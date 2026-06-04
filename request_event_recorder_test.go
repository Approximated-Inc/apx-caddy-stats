package apxstats

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestEventRecorder_BelowThreshold_KeepsAllSampleRate1(t *testing.T) {
	r := newRequestEventRecorder(1000, 10)
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
	r := newRequestEventRecorder(10000, 10)
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
	r := newRequestEventRecorder(5, 0) // threshold<=0 -> keep every row
	for i := 0; i < 20; i++ {
		r.record(requestEventRow{VhostID: uint32(i)})
	}
	rows, overflow := r.drain()
	require.Len(t, rows, 5)
	require.Equal(t, uint64(15), overflow)
}

func TestRequestEventRecorder_DrainResetsWindow(t *testing.T) {
	r := newRequestEventRecorder(5, 0)
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
	r2 := newRequestEventRecorder(1000, 10)
	for i := 0; i < 100; i++ {
		r2.record(requestEventRow{})
	}
	r2.drain() // exhaust window
	r2.record(requestEventRow{})
	rows, _ = r2.drain()
	require.Len(t, rows, 1)
	require.Equal(t, uint16(1), rows[0].SampleRate)
}

func TestRequestEventRecorder_Race(t *testing.T) {
	r := newRequestEventRecorder(100000, 10)
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
