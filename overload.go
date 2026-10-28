package apxstats

import (
	"fmt"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Overload control is node-local and process-global. Caddy builds a new
// StatsApp on every reload, so the controller lives at package level: state
// in atomics, config in an atomic pointer, one sampler goroutine refcounted
// by StatsApp.Start/Stop (Caddy starts the new generation before stopping
// the old, so a reload never drops the count to zero). No config reload is
// needed to change level.

// Overload modes, for both the WAF and admission.
const (
	overloadModeOff     = "off"
	overloadModeObserve = "observe"
	overloadModeEnforce = "enforce"
)

// OverloadConfig is apps.apx_stats.overload. Absent means disabled: the
// level reads 0 and nothing is skipped, shed or reported.
type OverloadConfig struct {
	// WAF is "off", "observe" (count would-skip, evaluate as usual) or
	// "enforce" (detect-mode WAF skipped at level ≥ 1; block-mode WAF skips
	// strictly-defined static assets). Empty means off.
	WAF string `json:"waf,omitempty"`
	// Admission configures http.handlers.apx_admission.
	Admission *AdmissionConfig `json:"admission,omitempty"`
	// Thresholds override the controller defaults. Phoenix does not emit
	// them, so tuning a default never churns config bytes.
	Thresholds *OverloadThresholds `json:"thresholds,omitempty"`
}

// AdmissionConfig is apps.apx_stats.overload.admission.
type AdmissionConfig struct {
	// Mode is "off", "observe" (count would-shed, admit) or "enforce".
	Mode string `json:"mode,omitempty"`
	// MinLimit is the adaptive limit's floor. Default 8.
	MinLimit int `json:"min_limit,omitempty"`
	// HardLimit overrides the hard in-flight cap. Default
	// max(256, MemTotal_MB × 2).
	HardLimit int `json:"hard_limit,omitempty"`
}

// OverloadThresholds are optional overrides; zero keeps the default.
type OverloadThresholds struct {
	ConserveThrottlePermille int `json:"conserve_throttle_permille,omitempty"`
	ShedThrottlePermille     int `json:"shed_throttle_permille,omitempty"`
	CalmThrottlePermille     int `json:"calm_throttle_permille,omitempty"`
	ConserveSchedMs          int `json:"conserve_sched_ms,omitempty"`
	ShedSchedMs              int `json:"shed_sched_ms,omitempty"`
	CalmSchedMs              int `json:"calm_sched_ms,omitempty"`
	BurstTteS                int `json:"burst_tte_s,omitempty"`
	EnterSamples             int `json:"enter_samples,omitempty"`
	DwellS                   int `json:"dwell_s,omitempty"`
	ConserveExitS            int `json:"conserve_exit_s,omitempty"`
	ShedExitS                int `json:"shed_exit_s,omitempty"`
}

func validOverloadMode(m string) bool {
	switch m {
	case "", overloadModeOff, overloadModeObserve, overloadModeEnforce:
		return true
	}
	return false
}

// Validate rejects unknown modes and negative thresholds.
func (c *OverloadConfig) Validate() error {
	if c == nil {
		return nil
	}
	if !validOverloadMode(c.WAF) {
		return fmt.Errorf("apx_stats overload: waf must be off, observe or enforce, got %q", c.WAF)
	}
	if c.Admission != nil {
		if !validOverloadMode(c.Admission.Mode) {
			return fmt.Errorf("apx_stats overload: admission.mode must be off, observe or enforce, got %q", c.Admission.Mode)
		}
		if c.Admission.MinLimit < 0 || c.Admission.HardLimit < 0 {
			return fmt.Errorf("apx_stats overload: admission limits must not be negative")
		}
	}
	if t := c.Thresholds; t != nil {
		for _, v := range []int{t.ConserveThrottlePermille, t.ShedThrottlePermille, t.CalmThrottlePermille,
			t.ConserveSchedMs, t.ShedSchedMs, t.CalmSchedMs, t.BurstTteS, t.EnterSamples, t.DwellS,
			t.ConserveExitS, t.ShedExitS} {
			if v < 0 {
				return fmt.Errorf("apx_stats overload: thresholds must not be negative")
			}
		}
	}
	return nil
}

// levelThresholds is the resolved form used by nextLevel.
type levelThresholds struct {
	conserveThrottle, shedThrottle, calmThrottle int
	conserveSched, shedSched, calmSched          time.Duration
	burstTte                                     float64
	enterSamples                                 int
	dwell, conserveExit, shedExit                time.Duration
}

func defaultLevelThresholds() levelThresholds {
	return levelThresholds{
		conserveThrottle: 100, shedThrottle: 300, calmThrottle: 50,
		conserveSched: 20 * time.Millisecond, shedSched: 100 * time.Millisecond, calmSched: 10 * time.Millisecond,
		burstTte:     300,
		enterSamples: 3,
		dwell:        30 * time.Second, conserveExit: 120 * time.Second, shedExit: 60 * time.Second,
	}
}

func resolveLevelThresholds(t *OverloadThresholds) levelThresholds {
	th := defaultLevelThresholds()
	if t == nil {
		return th
	}
	pick := func(v int, cur *int) {
		if v > 0 {
			*cur = v
		}
	}
	pickD := func(v int, unit time.Duration, cur *time.Duration) {
		if v > 0 {
			*cur = time.Duration(v) * unit
		}
	}
	pick(t.ConserveThrottlePermille, &th.conserveThrottle)
	pick(t.ShedThrottlePermille, &th.shedThrottle)
	pick(t.CalmThrottlePermille, &th.calmThrottle)
	pickD(t.ConserveSchedMs, time.Millisecond, &th.conserveSched)
	pickD(t.ShedSchedMs, time.Millisecond, &th.shedSched)
	pickD(t.CalmSchedMs, time.Millisecond, &th.calmSched)
	if t.BurstTteS > 0 {
		th.burstTte = float64(t.BurstTteS)
	}
	pick(t.EnterSamples, &th.enterSamples)
	pickD(t.DwellS, time.Second, &th.dwell)
	pickD(t.ConserveExitS, time.Second, &th.conserveExit)
	pickD(t.ShedExitS, time.Second, &th.shedExit)
	return th
}

// overloadRuntime is the resolved, immutable config the hot paths read.
type overloadRuntime struct {
	waf           string
	admission     string
	minLimit      int
	hardLimit     int
	thresholds    levelThresholds
	wafEnforce    bool
	wafObserve    bool
	admitEnforce  bool
	admitObserve  bool
	admissionLive bool
}

func resolveOverloadConfig(c *OverloadConfig, memTotalBytes uint64) *overloadRuntime {
	if c == nil {
		return nil
	}
	rt := &overloadRuntime{waf: c.WAF, admission: overloadModeOff, minLimit: 8, thresholds: resolveLevelThresholds(c.Thresholds)}
	if rt.waf == "" {
		rt.waf = overloadModeOff
	}
	if c.Admission != nil {
		if c.Admission.Mode != "" {
			rt.admission = c.Admission.Mode
		}
		if c.Admission.MinLimit > 0 {
			rt.minLimit = c.Admission.MinLimit
		}
		rt.hardLimit = c.Admission.HardLimit
	}
	if rt.hardLimit <= 0 {
		rt.hardLimit = defaultHardLimit(memTotalBytes)
	}
	if rt.minLimit > rt.hardLimit {
		rt.minLimit = rt.hardLimit
	}
	rt.wafEnforce = rt.waf == overloadModeEnforce
	rt.wafObserve = rt.waf == overloadModeObserve
	rt.admitEnforce = rt.admission == overloadModeEnforce
	rt.admitObserve = rt.admission == overloadModeObserve
	rt.admissionLive = rt.admitEnforce || rt.admitObserve
	return rt
}

// defaultHardLimit is max(256, MemTotal_MB × 2).
func defaultHardLimit(memTotalBytes uint64) int {
	mb := int(memTotalBytes >> 20)
	if mb*2 > 256 {
		return mb * 2
	}
	return 256
}

// Reason bits shipped in node_state.reasons.
const (
	reasonThrottle uint32 = 1
	reasonSched    uint32 = 2
	reasonBurstTte uint32 = 4
	reasonHardCap  uint32 = 8
)

// levelSample is one second's controller input.
type levelSample struct {
	throttlePermille int           // 10 s EWMA
	schedP99         time.Duration // over the last 10 s
	tte              float64       // seconds to an empty burst balance; < 0 = none
	hardCap          bool          // admission hit the hard cap this second
}

// levelState is the controller's memory between samples.
type levelState struct {
	level        int
	since        time.Time // when the current level was entered
	streak1      int       // consecutive samples with any level-1 enter term
	streak2      int       // consecutive samples with a level-2 enter term
	l2ClearSince time.Time // first sample of the current run without level-2 terms
	calmSince    time.Time // first sample of the current calm run
	reasons      uint32    // terms true in the latest sample
}

// nextLevel is the pure level transition. Entering a higher level needs
// its condition on enterSamples consecutive samples and is never delayed by
// dwell. Leaving a level needs dwell at it, plus 60 s without level-2 terms
// (2 → 1) or 120 s calm (1 → 0). Level 2 always falls to 1 first.
func nextLevel(st levelState, s levelSample, now time.Time, th levelThresholds) levelState {
	var r uint32
	if s.throttlePermille >= th.conserveThrottle {
		r |= reasonThrottle
	}
	if s.schedP99 >= th.conserveSched {
		r |= reasonSched
	}
	if s.tte >= 0 && s.tte < th.burstTte {
		r |= reasonBurstTte
	}
	if s.hardCap {
		r |= reasonHardCap
	}
	l2 := s.throttlePermille >= th.shedThrottle || s.schedP99 >= th.shedSched
	l1 := l2 || r&(reasonThrottle|reasonSched|reasonBurstTte) != 0
	if l2 {
		st.streak2++
		st.l2ClearSince = time.Time{}
	} else {
		st.streak2 = 0
		if st.l2ClearSince.IsZero() {
			st.l2ClearSince = now
		}
	}
	if l1 {
		st.streak1++
	} else {
		st.streak1 = 0
	}
	calm := !l1 && s.throttlePermille < th.calmThrottle && s.schedP99 < th.calmSched
	if calm {
		if st.calmSince.IsZero() {
			st.calmSince = now
		}
	} else {
		st.calmSince = time.Time{}
	}
	dwellOK := now.Sub(st.since) >= th.dwell
	switch {
	case st.level < 2 && st.streak2 >= th.enterSamples:
		st.level, st.since = 2, now
	case st.level < 1 && st.streak1 >= th.enterSamples:
		st.level, st.since = 1, now
	case st.level == 2 && dwellOK && !st.l2ClearSince.IsZero() && now.Sub(st.l2ClearSince) >= th.shedExit:
		st.level, st.since = 1, now
	case st.level == 1 && dwellOK && !st.calmSince.IsZero() && now.Sub(st.calmSince) >= th.conserveExit:
		st.level, st.since = 0, now
	}
	st.reasons = r
	return st
}

// overloadController is the package-level singleton.
type overloadController struct {
	cfg   atomic.Pointer[overloadRuntime]
	level atomic.Int32

	mu      sync.Mutex
	refs    int
	stop    chan struct{}
	done    chan struct{}
	signals overloadSignals

	// Sampler-goroutine state (touched only by sampleOnce).
	sampler samplerState
}

var overload = &overloadController{signals: procSignals{}}

// overloadSampleInterval is a var so tests can run the real sampler fast.
var overloadSampleInterval = time.Second

// hardCapHit is set by admission when it sheds at the hard cap; the sampler
// folds it into reasons and clears it.
var hardCapHit atomic.Bool

// admissionInflight is the admission handler's in-flight count.
var admissionInflight atomic.Int64

// admissionLimitNow is the adaptive limit admission last applied (0 none).
var admissionLimitNow atomic.Int64

// Level returns the current level, 0 when overload control is disabled.
func (c *overloadController) Level() int {
	if c.cfg.Load() == nil {
		return 0
	}
	return int(c.level.Load())
}

// applyOverloadConfig stores the config every hot path reads. Called from
// StatsApp.Start, so a load that fails before Start never changes it.
func applyOverloadConfig(c *OverloadConfig) {
	rt := resolveOverloadConfig(c, clampTotalRAM(detectTotalRAM()))
	overload.cfg.Store(rt)
	if rt == nil {
		overload.level.Store(0)
		metricOverloadLevel.Set(0)
	}
}

// overloadRetain starts the sampler on the first live app.
func overloadRetain() {
	c := overload
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refs++
	if c.refs == 1 {
		c.stop = make(chan struct{})
		c.done = make(chan struct{})
		go c.sampleLoop(c.stop, c.done, c.signals)
	}
}

// overloadRelease stops the sampler when the last app stops.
func overloadRelease() {
	c := overload
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refs == 0 {
		return
	}
	c.refs--
	if c.refs == 0 {
		close(c.stop)
	}
}

func (c *overloadController) samplerRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refs == 0 || c.done == nil {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (c *overloadController) sampleLoop(stop, done chan struct{}, sig overloadSignals) {
	defer close(done)
	c.sampler = samplerState{}
	t := time.NewTicker(overloadSampleInterval)
	defer t.Stop()
	c.sampleOnce(time.Now(), sig)
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			c.sampleOnce(now, sig)
		}
	}
}

// samplerState carries deltas and model state between samples.
type samplerState struct {
	last         time.Time
	prevStat     cpuTimes
	havePrevStat bool
	prevThr      uint64
	havePrevThr  bool
	ewma         float64
	haveEWMA     bool
	sched        schedWindow
	burst        *burstModel
	level        levelState
	busy         float64
}

// sampleOnce reads the signals, advances the models and publishes the level.
func (c *overloadController) sampleOnce(now time.Time, sig overloadSignals) {
	rt := c.cfg.Load()
	s := &c.sampler
	if rt == nil {
		// Disabled: forget everything so a later enable starts uncalibrated.
		*s = samplerState{}
		c.level.Store(0)
		nodeStates.reset()
		return
	}
	dt := 0.0
	if !s.last.IsZero() {
		dt = now.Sub(s.last).Seconds()
	}
	gap := dt > 10
	s.last = now

	vcpus := float64(runtime.NumCPU())
	instPermille := 0
	if st, ok := sig.procStat(); ok {
		if s.havePrevStat && !gap {
			steal, busy, ok := stealAndBusy(s.prevStat, st, dt)
			if ok {
				instPermille = steal
				s.busy = busy
			}
		}
		s.prevStat, s.havePrevStat = st, true
	}
	if thr, ok := sig.cgroupThrottledUsec(); ok {
		if s.havePrevThr && !gap && dt > 0 && thr >= s.prevThr {
			p := int(math.Min(1, float64(thr-s.prevThr)/(dt*1e6)) * 1000)
			if p > instPermille {
				instPermille = p
			}
		}
		s.prevThr, s.havePrevThr = thr, true
	}
	if !s.haveEWMA || gap {
		s.ewma, s.haveEWMA = float64(instPermille), true
	} else if dt > 0 {
		alpha := 1 - math.Exp(-dt/10)
		s.ewma += alpha * (float64(instPermille) - s.ewma)
	}
	sched := time.Duration(0)
	if counts, buckets, ok := sig.schedHistogram(); ok {
		sched = s.sched.push(counts, buckets)
	}
	if s.burst == nil {
		up, ok := sig.uptime()
		if !ok {
			up = -1
		}
		s.burst = newBurstModel(vcpus, up, now)
	} else {
		s.burst.step(now, s.busy, instPermille)
	}
	tte := s.burst.tte(s.busy)
	s.level = nextLevel(s.level, levelSample{
		throttlePermille: int(math.Round(s.ewma)),
		schedP99:         sched,
		tte:              tte,
		hardCap:          hardCapHit.Swap(false),
	}, now, rt.thresholds)
	c.level.Store(int32(s.level.level))
	metricOverloadLevel.Set(float64(s.level.level))

	est := int64(-1) // unknown, or not draining
	if tte >= 0 {
		est = int64(tte)
	}
	nodeStates.observe(now, nodeStateSample{
		level:          s.level.level,
		reasons:        s.level.reasons,
		schedUs:        sched.Microseconds(),
		burstEstS:      est,
		burstModel:     s.burst.state.String(),
		inflight:       admissionInflight.Load(),
		admissionLimit: admissionLimitNow.Load(),
		gomaxprocs:     runtime.GOMAXPROCS(0),
	})
}
