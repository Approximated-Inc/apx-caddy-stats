package apxstats

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A calibrated shared-cpu-4x node a hair above baseline: tte ≈ 2.7e9 s,
// past Int32, which made the ingest drop the whole node_state row.
func TestBurstEstimateFitsInt32(t *testing.T) {
	m := &burstModel{vcpus: 4, state: burstCalibrated, b: 2000}
	tte := m.tte(m.baseline() + 7.5e-7)
	require.Greater(t, tte, float64(math.MaxInt32))
	est := burstEstSeconds(tte)
	require.LessOrEqual(t, est, int64(math.MaxInt32))
	require.EqualValues(t, maxBurstEstS, est)
	require.EqualValues(t, -1, burstEstSeconds(-1))
	require.EqualValues(t, 120, burstEstSeconds(120.7))
}

func currentWAFMode() string {
	if rt := overload.cfg.Load(); rt != nil {
		return rt.waf
	}
	return ""
}

// A load that fails after apx_stats started: Caddy stops the new apps and
// keeps serving the old config, so the old app's overload config must come
// back, not stay on the rejected one.
func TestOverloadFailedReloadRestoresSurvivingConfig(t *testing.T) {
	resetOverload(t)
	old := overloadRetain(&OverloadConfig{WAF: "observe"})
	defer overloadRelease(old)
	require.Equal(t, "observe", currentWAFMode())

	rejected := overloadRetain(&OverloadConfig{WAF: "enforce"})
	require.Equal(t, "enforce", currentWAFMode())
	overloadRelease(rejected) // the failed load's apps are stopped
	require.Equal(t, "observe", currentWAFMode(), "surviving generation's config")

	// A normal reload stops the older app: the newer config stays.
	next := overloadRetain(&OverloadConfig{WAF: "enforce"})
	defer overloadRelease(next)
	overloadRelease(old)
	require.Equal(t, "enforce", currentWAFMode())
}

// The same through StatsApp Start/Stop.
func TestStatsAppFailedReloadRestoresOverloadConfig(t *testing.T) {
	resetOverload(t)
	server, _ := captureServer(t, 200)
	defer server.Close()
	app1 := newTestApp(t, server.URL, "k", func(a *StatsApp) { a.Overload = &OverloadConfig{WAF: "observe"} })
	require.NoError(t, app1.Start())
	defer app1.Stop()
	app2 := newTestApp(t, server.URL, "k", func(a *StatsApp) {
		a.Overload = &OverloadConfig{WAF: "enforce", Admission: &AdmissionConfig{Mode: "enforce"}}
	})
	require.NoError(t, app2.Start())
	require.True(t, overload.cfg.Load().admitEnforce)
	require.NoError(t, app2.Stop())
	require.Equal(t, "observe", currentWAFMode())
	require.False(t, overload.cfg.Load().admitEnforce)
}

// Removing apx_stats (the last live app stops) turns control off, so an
// elevated level can't keep the WAF skipping with no sampler to lower it.
func TestOverloadLastReleaseClearsLevel(t *testing.T) {
	resetOverload(t)
	o := overloadRetain(&OverloadConfig{WAF: "enforce"})
	overload.level.Store(2)
	require.Equal(t, 2, overload.Level())
	overloadRelease(o)
	require.Equal(t, 0, overload.Level())
	require.Nil(t, overload.cfg.Load())
	require.False(t, (&OverloadBridge{}).SkipWAF(get(t, "/app.js"), false))
}

// blockingSignals holds the first sample until released.
type blockingSignals struct {
	fakeSignals
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *blockingSignals) procStat() (cpuTimes, bool) {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return cpuTimes{}, false
}

// Removing and re-adding the app at once must not run two samplers on the
// shared sampler state: the new one starts after the old one has exited.
func TestOverloadRetainWaitsForPreviousSampler(t *testing.T) {
	resetOverload(t)
	origSig, origInterval := overload.signals, overloadSampleInterval
	sig := &blockingSignals{entered: make(chan struct{}), release: make(chan struct{})}
	overload.signals, overloadSampleInterval = sig, time.Millisecond
	defer func() { overload.signals, overloadSampleInterval = origSig, origInterval }()

	first := overloadRetain(&OverloadConfig{WAF: "observe"})
	<-sig.entered // the first sampler is mid-sample
	overloadRelease(first)

	started := make(chan *overloadOwner)
	go func() { started <- overloadRetain(&OverloadConfig{WAF: "observe"}) }()
	select {
	case <-started:
		t.Fatal("a second sampler started while the first was still sampling")
	case <-time.After(50 * time.Millisecond):
	}
	close(sig.release)
	select {
	case o := <-started:
		overloadRelease(o)
	case <-time.After(2 * time.Second):
		t.Fatal("retain never started the new sampler")
	}
	overload.mu.Lock()
	done := overload.done
	overload.mu.Unlock()
	<-done // before the deferred restore of the signals and interval
}
