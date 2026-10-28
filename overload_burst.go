package apxstats

import (
	"math"
	"time"
)

// burstState: "unknown is a state". Only a calibrated model can trigger.
type burstState int

const (
	burstUncalibrated burstState = iota
	burstCalibrated
	burstUnthrottled
)

func (s burstState) String() string {
	switch s {
	case burstCalibrated:
		return "calibrated"
	case burstUnthrottled:
		return "unthrottled"
	default:
		return "uncalibrated"
	}
}

const (
	burstInitialPerVCPU = 50.0  // Phase 0 initial balance, CPU-seconds per vCPU
	burstMaxPerVCPU     = 500.0 // cap, CPU-seconds per vCPU
	burstFreshUptimeS   = 120.0 // a process this young starts on a fresh machine
	burstMaxGapS        = 10.0  // a longer sample gap (suspend/resume) loses calibration
	burstOnsetPermille  = 200
	burstOnsetSamples   = 3
)

// burstModel tracks a Fly shared-CPU burst balance:
// b ← clamp(b + (vcpus/16 − busy)·dt, 0, 500·vcpus).
type burstModel struct {
	vcpus        float64
	state        burstState
	b            float64
	last         time.Time
	onset        int
	drainNoSteal float64 // net drain above baseline with zero steal
}

// newBurstModel starts calibrated at 50·vcpus on a fresh machine (uptime
// < 120 s); otherwise the balance is unknown.
func newBurstModel(vcpus, uptimeS float64, now time.Time) *burstModel {
	m := &burstModel{vcpus: vcpus, last: now}
	if uptimeS >= 0 && uptimeS < burstFreshUptimeS {
		m.state, m.b = burstCalibrated, burstInitialPerVCPU*vcpus
	}
	return m
}

func (m *burstModel) baseline() float64 { return m.vcpus / 16 }

// step advances the model by one sample. stealPermille is the instant
// (not smoothed) throttle share.
func (m *burstModel) step(now time.Time, busy float64, stealPermille int) {
	dt := now.Sub(m.last).Seconds()
	m.last = now
	if dt > burstMaxGapS {
		m.state, m.b, m.onset, m.drainNoSteal = burstUncalibrated, 0, 0, 0
		return
	}
	if dt <= 0 {
		return
	}
	base := m.baseline()
	if stealPermille >= burstOnsetPermille && busy >= base {
		m.onset++
	} else {
		m.onset = 0
	}
	if m.onset >= burstOnsetSamples {
		// Throttling has started: the balance is empty, whatever we thought.
		m.state, m.b, m.drainNoSteal = burstCalibrated, 0, 0
		return
	}
	if stealPermille > 0 {
		m.drainNoSteal = 0
	} else {
		m.drainNoSteal += (busy - base) * dt
		if m.drainNoSteal < 0 {
			m.drainNoSteal = 0
		}
		// Drained more than the largest balance and never throttled:
		// performance CPU, or a bigger balance than modelled.
		if m.drainNoSteal > burstMaxPerVCPU*m.vcpus {
			m.state = burstUnthrottled
		}
	}
	if m.state == burstCalibrated {
		m.b += (base - busy) * dt
		if m.b < 0 {
			m.b = 0
		}
		if ceiling := burstMaxPerVCPU * m.vcpus; m.b > ceiling {
			m.b = ceiling
		}
	}
}

// tte is the predicted seconds until the balance empties, or -1 when the
// model is not calibrated or the node is not draining.
func (m *burstModel) tte(busy float64) float64 {
	base := m.baseline()
	if m.state != burstCalibrated || busy <= base {
		return -1
	}
	return m.b / (busy - base)
}

// maxBurstEstS caps the reported time-to-empty. busy a hair above the
// baseline gives an estimate past Int32, which the ingest rejects with the
// whole node_state row; anything this far out never triggers anyway.
const maxBurstEstS = 1_000_000

// burstEstSeconds is the node_state burst_est_s value: -1 when unknown or
// not draining, otherwise tte in whole seconds, capped at maxBurstEstS.
func burstEstSeconds(tte float64) int64 {
	switch {
	case tte < 0 || math.IsNaN(tte):
		return -1
	case tte >= maxBurstEstS:
		return maxBurstEstS
	}
	return int64(tte)
}
