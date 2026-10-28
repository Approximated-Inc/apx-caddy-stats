package apxstats

import (
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

// resetOverload puts the package-level controller back to disabled and
// zeroes every counter, so tests don't leak state into each other.
func resetOverload(t *testing.T) {
	t.Helper()
	clear := func() {
		overload.cfg.Store(nil)
		overload.level.Store(0)
		nodeStates.reset()
		overloadCounts.wafSkippedDetect.Store(0)
		overloadCounts.wafSkippedStatic.Store(0)
		overloadCounts.wafWouldSkip.Store(0)
		overloadCounts.wouldShed.Store(0)
		for i := range overloadCounts.shed {
			overloadCounts.shed[i].Store(0)
		}
		admissionInflight.Store(0)
		admissionLimitNow.Store(0)
		hardCapHit.Store(false)
	}
	clear()
	t.Cleanup(clear)
}

func setOverload(t *testing.T, cfg *OverloadConfig, level int) {
	t.Helper()
	overload.cfg.Store(resolveOverloadConfig(cfg, 1<<30))
	overload.level.Store(int32(level))
}

// B1: the level state machine.
func TestNextLevel(t *testing.T) {
	th := defaultLevelThresholds()
	t0 := time.Unix(1_000_000, 0)
	hot := levelSample{throttlePermille: 150, tte: -1}
	shed := levelSample{throttlePermille: 350, tte: -1}
	calm := levelSample{tte: -1}
	run := func(st levelState, s levelSample, from time.Time, n int) (levelState, time.Time) {
		now := from
		for i := 0; i < n; i++ {
			now = now.Add(time.Second)
			st = nextLevel(st, s, now, th)
		}
		return st, now
	}

	t.Run("enter needs 3 consecutive samples", func(t *testing.T) {
		st, now := run(levelState{}, hot, t0, 2)
		require.Equal(t, 0, st.level)
		st = nextLevel(st, calm, now.Add(time.Second), th) // breaks the streak
		st, _ = run(st, hot, now.Add(time.Second), 2)
		require.Equal(t, 0, st.level)
		st, _ = run(st, hot, now.Add(3*time.Second), 1)
		require.Equal(t, 1, st.level)
	})
	t.Run("straight to 2, reasons", func(t *testing.T) {
		st, _ := run(levelState{}, levelSample{throttlePermille: 400, schedP99: 120 * time.Millisecond, tte: 10, hardCap: true}, t0, 3)
		require.Equal(t, 2, st.level)
		require.Equal(t, reasonThrottle|reasonSched|reasonBurstTte|reasonHardCap, st.reasons)
		st, _ = run(st, levelSample{schedP99: 25 * time.Millisecond, tte: -1}, t0.Add(10*time.Second), 1)
		require.Equal(t, reasonSched, st.reasons)
	})
	t.Run("sched and tte each enter level 1", func(t *testing.T) {
		st, _ := run(levelState{}, levelSample{schedP99: 20 * time.Millisecond, tte: -1}, t0, 3)
		require.Equal(t, 1, st.level)
		st, _ = run(levelState{}, levelSample{tte: 299}, t0, 3)
		require.Equal(t, 1, st.level)
		st, _ = run(levelState{}, levelSample{tte: 301}, t0, 3)
		require.Equal(t, 0, st.level)
	})
	t.Run("level 1 exits 120 s after the first calm sample, not before", func(t *testing.T) {
		st, now := run(levelState{}, hot, t0, 3)
		require.Equal(t, 1, st.level)
		st, now = run(st, calm, now, 120) // 119 s since the first calm sample
		require.Equal(t, 1, st.level)
		st, _ = run(st, calm, now, 1)
		require.Equal(t, 0, st.level)
	})
	t.Run("calm needs throttle under 50", func(t *testing.T) {
		st, now := run(levelState{}, hot, t0, 3)
		st, _ = run(st, levelSample{throttlePermille: 60, tte: -1}, now, 300)
		require.Equal(t, 1, st.level, "60‰ is below the enter bar but not calm")
	})
	t.Run("level 2 falls to 1 after 60 s and dwell", func(t *testing.T) {
		st, now := run(levelState{}, shed, t0, 3)
		require.Equal(t, 2, st.level)
		st, now = run(st, hot, now, 60) // 59 s since the first sample without L2 terms
		require.Equal(t, 2, st.level)
		st, now = run(st, hot, now, 1)
		require.Equal(t, 1, st.level)
		st, _ = run(st, calm, now, 400)
		require.Equal(t, 0, st.level)
	})
	t.Run("dwell holds a level even when the exit hold is met", func(t *testing.T) {
		short := th
		short.shedExit = 5 * time.Second
		st := levelState{}
		now := t0
		for i := 0; i < 3; i++ {
			now = now.Add(time.Second)
			st = nextLevel(st, shed, now, short)
		}
		require.Equal(t, 2, st.level)
		for i := 0; i < 29; i++ {
			now = now.Add(time.Second)
			st = nextLevel(st, hot, now, short)
		}
		require.Equal(t, 2, st.level, "29 s at level 2 < 30 s dwell")
		st = nextLevel(st, hot, now.Add(time.Second), short)
		require.Equal(t, 1, st.level)
	})
}

// B2: the burst model.
func TestBurstModel(t *testing.T) {
	t0 := time.Unix(2_000_000, 0)
	vcpus := 1.0
	base := vcpus / 16
	step := func(m *burstModel, from time.Time, n int, busy float64, steal int) time.Time {
		now := from
		for i := 0; i < n; i++ {
			now = now.Add(time.Second)
			m.step(now, busy, steal)
		}
		return now
	}

	t.Run("old process starts uncalibrated and never triggers", func(t *testing.T) {
		m := newBurstModel(vcpus, 5000, t0)
		require.Equal(t, burstUncalibrated, m.state)
		step(m, t0, 100, 1.0, 0)
		require.Equal(t, -1.0, m.tte(1.0))
	})
	t.Run("fresh process starts calibrated at 50·vcpus", func(t *testing.T) {
		m := newBurstModel(vcpus, 30, t0)
		require.Equal(t, burstCalibrated, m.state)
		require.InDelta(t, 50.0, m.b, 1e-9)
		require.InDelta(t, 50/(1-base), m.tte(1.0), 1e-9)
		step(m, t0, 10, 1.0, 0)
		require.InDelta(t, 50-10*(1-base), m.b, 1e-6)
	})
	t.Run("steal onset calibrates to 0", func(t *testing.T) {
		m := newBurstModel(vcpus, 5000, t0)
		now := step(m, t0, 2, 1.0, 900)
		require.Equal(t, burstUncalibrated, m.state, "2 samples are not an onset")
		step(m, now, 1, 1.0, 900)
		require.Equal(t, burstCalibrated, m.state)
		require.Zero(t, m.b)
		require.Zero(t, m.tte(1.0))
	})
	t.Run("gap over 10 s loses calibration", func(t *testing.T) {
		m := newBurstModel(vcpus, 30, t0)
		m.step(t0.Add(11*time.Second), 0.5, 0)
		require.Equal(t, burstUncalibrated, m.state)
	})
	t.Run("long drain without steal is unthrottled", func(t *testing.T) {
		m := newBurstModel(vcpus, 30, t0)
		// 500 CPU-seconds above a 1/16 baseline at 1 core busy ≈ 534 s.
		now := step(m, t0, 530, 1.0, 0)
		require.Equal(t, burstCalibrated, m.state)
		step(m, now, 10, 1.0, 0)
		require.Equal(t, burstUnthrottled, m.state)
		require.Equal(t, -1.0, m.tte(1.0))
	})
	t.Run("balance refills and caps", func(t *testing.T) {
		m := newBurstModel(vcpus, 30, t0)
		step(m, t0, 20_000, 0, 0)
		require.InDelta(t, 500.0, m.b, 1e-6)
	})
}

// B3: /proc/stat parsing on the Phase 0 lines (a Fly shared VM throttled
// while burning): steal ‰ and busy cores by hand arithmetic.
func TestProcStatPhase0(t *testing.T) {
	a, err := os.ReadFile("testdata/procstat_phase0_a")
	require.NoError(t, err)
	b, err := os.ReadFile("testdata/procstat_phase0_b")
	require.NoError(t, err)
	pa, ok := parseProcStat(a)
	require.True(t, ok)
	pb, ok := parseProcStat(b)
	require.True(t, ok)
	require.Equal(t, cpuTimes{user: 6048, system: 97, idle: 2552, iowait: 206, softirq: 8, steal: 6631}, pa)
	steal, busy, ok := stealAndBusy(pa, pb, 60)
	require.True(t, ok)
	// Δuser 465 + Δsystem 35 + Δsoftirq 13 + Δsteal 5643 = 6156 ticks.
	require.Equal(t, 5643*1000/6156, steal)
	require.InDelta(t, float64(465+35+13)/100/60, busy, 1e-9)

	_, ok = parseProcStat([]byte("intr 1 2 3\n"))
	require.False(t, ok)
	thr, ok := parseCgroupThrottled([]byte("usage_usec 10\nnr_throttled 3\nthrottled_usec 4500\n"))
	require.True(t, ok)
	require.EqualValues(t, 4500, thr)
	up, ok := parseUptime([]byte("98.12 50.00\n"))
	require.True(t, ok)
	require.InDelta(t, 98.12, up, 1e-9)
}

// B4: sched p99 is computed on the delta between histograms.
func TestSchedP99Delta(t *testing.T) {
	buckets := []float64{0, 0.001, 0.01, 0.1, 1, 1e300}
	prev := []uint64{0, 0, 0, 1000, 0} // an old burst of 100 ms–1 s latencies
	cur := []uint64{980, 15, 5, 1000, 0}
	require.Equal(t, 10*time.Millisecond, schedP99(prev, cur, buckets),
		"the delta has 1000 samples, 99% under 10 ms; the cumulative histogram's p99 would be 1 s")
	require.Zero(t, schedP99(cur, cur, buckets))
	require.Equal(t, time.Second, schedP99([]uint64{0, 0, 0, 0, 0}, []uint64{0, 0, 0, 0, 5}, buckets), "+Inf bucket reports its lower bound")

	var w schedWindow
	require.Zero(t, w.push(prev, buckets))
	require.Equal(t, 10*time.Millisecond, w.push(cur, buckets))
}

// fakeSignals reports 1 s scheduler latencies on every sample.
type fakeSignals struct {
	mu   sync.Mutex
	n    uint64
	calm bool
}

func (f *fakeSignals) procStat() (cpuTimes, bool)          { return cpuTimes{}, false }
func (f *fakeSignals) cgroupThrottledUsec() (uint64, bool) { return 0, false }
func (f *fakeSignals) uptime() (float64, bool)             { return 5000, true }
func (f *fakeSignals) schedHistogram() ([]uint64, []float64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.calm {
		f.n += 100
	}
	return []uint64{0, 0, f.n}, []float64{0, 0.01, 0.5, 1e300}, true
}

// B5: the controller is process-global and survives a reload.
func TestOverloadControllerSurvivesReload(t *testing.T) {
	resetOverload(t)
	origSig, origInterval := overload.signals, overloadSampleInterval
	sig := &fakeSignals{}
	overload.signals, overloadSampleInterval = sig, 5*time.Millisecond
	defer func() { overload.signals, overloadSampleInterval = origSig, origInterval }()

	server, _ := captureServer(t, 200)
	defer server.Close()
	cfg := &OverloadConfig{WAF: "enforce"}
	app1 := newTestApp(t, server.URL, "k", func(a *StatsApp) { a.Overload = cfg })
	require.NoError(t, app1.Start())
	require.Eventually(t, func() bool { return overload.Level() == 2 }, 2*time.Second, 5*time.Millisecond)
	sig.mu.Lock()
	sig.calm = true // from here only held state (dwell, exit hold) keeps level 2
	sig.mu.Unlock()

	app2 := newTestApp(t, server.URL, "k", func(a *StatsApp) { a.Overload = cfg })
	require.NoError(t, app2.Start())
	require.NoError(t, app1.Stop())
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 2, overload.Level(), "level kept across the reload")
	require.True(t, overload.samplerRunning(), "sampler alive while app2 runs")

	require.NoError(t, app2.Stop())
	require.Eventually(t, func() bool { return !overload.samplerRunning() }, time.Second, 5*time.Millisecond)
}

// An app without an overload block disables control (level reads 0).
func TestOverloadDisabledWithoutBlock(t *testing.T) {
	resetOverload(t)
	setOverload(t, &OverloadConfig{WAF: "enforce"}, 2)
	require.Equal(t, 2, overload.Level())
	applyOverloadConfig(nil)
	require.Equal(t, 0, overload.Level())
}

func TestOverloadConfigValidate(t *testing.T) {
	for _, ok := range []*OverloadConfig{nil, {}, {WAF: "observe"}, {WAF: "enforce", Admission: &AdmissionConfig{Mode: "observe"}}} {
		require.NoError(t, ok.Validate())
	}
	for _, bad := range []*OverloadConfig{{WAF: "on"}, {Admission: &AdmissionConfig{Mode: "shed"}}, {Thresholds: &OverloadThresholds{DwellS: -1}}} {
		require.Error(t, bad.Validate())
	}
	require.Equal(t, 256, defaultHardLimit(64<<20))
	require.Equal(t, 4096, defaultHardLimit(2048<<20))
}

// B7: SkipWAF.
func TestOverloadBridgeSkipWAF(t *testing.T) {
	resetOverload(t)
	b := &OverloadBridge{}
	static := func() *http.Request { r, _ := http.NewRequest("GET", "http://x/app.js", nil); return r }
	page := func() *http.Request { r, _ := http.NewRequest("GET", "http://x/login", nil); return r }

	setOverload(t, &OverloadConfig{WAF: "enforce"}, 0)
	require.False(t, b.SkipWAF(page(), false), "level 0")

	setOverload(t, &OverloadConfig{WAF: "enforce"}, 1)
	require.True(t, b.SkipWAF(page(), false), "detect route skips everything")
	require.False(t, b.SkipWAF(page(), true), "block route skips only safe statics")
	require.True(t, b.SkipWAF(static(), true))
	require.EqualValues(t, 1, overloadCounts.wafSkippedDetect.Load())
	require.EqualValues(t, 1, overloadCounts.wafSkippedStatic.Load())

	setOverload(t, &OverloadConfig{WAF: "observe"}, 2)
	require.False(t, b.SkipWAF(page(), false))
	require.False(t, b.SkipWAF(static(), true))
	require.EqualValues(t, 2, overloadCounts.wafWouldSkip.Load())

	setOverload(t, &OverloadConfig{WAF: "off"}, 2)
	require.False(t, b.SkipWAF(page(), false))
	overload.cfg.Store(nil)
	require.False(t, b.SkipWAF(page(), false))
}

// B9: the Coraza fork finds apx.overload through caddy.GetModule and needs
// exactly this method set.
func TestOverloadBridgeModuleResolves(t *testing.T) {
	info, err := caddy.GetModule("apx.overload")
	require.NoError(t, err)
	_, ok := info.New().(interface {
		SkipWAF(*http.Request, bool) bool
	})
	require.True(t, ok)
}
