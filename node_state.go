package apxstats

import (
	"compress/gzip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// node_state rows: one per completed minute with a non-normal level or a
// non-zero counter, plus a heartbeat every 10 minutes while normal (so a
// live, normal node is distinguishable from an unknown one). Raw CPU and
// memory are deliberately absent: node telemetry (approximated #410) reports
// those. Rows ride the existing stats POST.

const (
	nodeStateHeartbeatMinutes = 10
	nodeStateMaxReady         = 30 // completed minutes held between drains
)

// Counter order in nodeStateMinute.counts and on the wire.
const (
	nsWafSkippedDetect = iota
	nsWafSkippedStatic
	nsWafWouldSkip
	nsShedP0
	nsShedP1
	nsShedP2
	nsShedP3
	nsWouldShed
	nsCounters
)

var nodeStateCounterNames = [nsCounters]string{
	"waf_skipped_detect", "waf_skipped_static", "waf_would_skip",
	"shed_p0", "shed_p1", "shed_p2", "shed_p3", "would_shed",
}

func snapshotOverloadCounts() (c [nsCounters]uint64) {
	c[nsWafSkippedDetect] = overloadCounts.wafSkippedDetect.Load()
	c[nsWafSkippedStatic] = overloadCounts.wafSkippedStatic.Load()
	c[nsWafWouldSkip] = overloadCounts.wafWouldSkip.Load()
	for i := 0; i < 4; i++ {
		c[nsShedP0+i] = overloadCounts.shed[i].Load()
	}
	c[nsWouldShed] = overloadCounts.wouldShed.Load()
	return c
}

// nodeStateSample is one sampler second.
type nodeStateSample struct {
	level          int
	reasons        uint32
	schedUs        int64
	burstEstS      int64 // -1 unknown
	burstModel     string
	inflight       int64
	admissionLimit int64 // 0 when no adaptive limit applied
	gomaxprocs     int
}

// nodeStateMinute is one minute's aggregate.
type nodeStateMinute struct {
	ts                uint32 // unix minute
	levelMax          int
	l1Seconds         int
	l2Seconds         int
	reasons           uint32
	schedP99UsMax     int64
	burstEstSMin      int64
	burstModel        string
	inflightMax       int64
	admissionLimitMin int64
	counts            [nsCounters]uint64
	gomaxprocs        int
}

func (m *nodeStateMinute) worthShipping() bool {
	if m.levelMax > 0 || m.ts%nodeStateHeartbeatMinutes == 0 {
		return true
	}
	for _, c := range m.counts {
		if c > 0 {
			return true
		}
	}
	return false
}

// nodeStateAccumulator is package-level (it outlives StatsApp reloads); the
// first app to flush after a minute completes takes its row.
type nodeStateAccumulator struct {
	mu    sync.Mutex
	cur   *nodeStateMinute
	base  [nsCounters]uint64
	ready []nodeStateMinute
}

var nodeStates = &nodeStateAccumulator{}

func (a *nodeStateAccumulator) observe(now time.Time, s nodeStateSample) {
	minute := uint32(now.Unix() / 60)
	counts := snapshotOverloadCounts()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cur != nil && a.cur.ts != minute {
		done := *a.cur
		for i := range done.counts {
			done.counts[i] = counts[i] - a.base[i]
		}
		if done.worthShipping() {
			if len(a.ready) >= nodeStateMaxReady {
				a.ready = a.ready[1:]
			}
			a.ready = append(a.ready, done)
		}
		a.cur = nil
	}
	if a.cur == nil {
		a.cur = &nodeStateMinute{ts: minute, burstEstSMin: -1}
		a.base = counts
	}
	m := a.cur
	if s.level > m.levelMax {
		m.levelMax = s.level
	}
	switch s.level {
	case 1:
		m.l1Seconds++
	case 2:
		m.l2Seconds++
	}
	m.reasons |= s.reasons
	if s.schedUs > m.schedP99UsMax {
		m.schedP99UsMax = s.schedUs
	}
	if s.burstEstS >= 0 && (m.burstEstSMin < 0 || s.burstEstS < m.burstEstSMin) {
		m.burstEstSMin = s.burstEstS
	}
	m.burstModel = s.burstModel
	if s.inflight > m.inflightMax {
		m.inflightMax = s.inflight
	}
	if s.admissionLimit > 0 && (m.admissionLimitMin == 0 || s.admissionLimit < m.admissionLimitMin) {
		m.admissionLimitMin = s.admissionLimit
	}
	m.gomaxprocs = s.gomaxprocs
}

// drain returns the completed minutes and forgets them. The current minute
// is never returned.
func (a *nodeStateAccumulator) drain() []nodeStateMinute {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.ready
	a.ready = nil
	return out
}

func (a *nodeStateAccumulator) reset() {
	a.mu.Lock()
	a.cur, a.ready = nil, nil
	a.mu.Unlock()
}

func drainNodeStateRows() []nodeStateMinute { return nodeStates.drain() }

func encodeNodeStateRow(w *gzip.Writer, ps uint32, machineID string, m nodeStateMinute) error {
	var b strings.Builder
	b.Grow(512)
	b.WriteByte('{')
	writeString(&b, "_type", "node_state")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(m.ts))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "machine_id", machineID)
	writeInt := func(key string, v int64) {
		b.WriteByte(',')
		b.WriteByte('"')
		b.WriteString(key)
		b.WriteString(`":`)
		b.WriteString(strconv.FormatInt(v, 10))
	}
	writeInt("level_max", int64(m.levelMax))
	writeInt("l1_seconds", int64(m.l1Seconds))
	writeInt("l2_seconds", int64(m.l2Seconds))
	writeInt("reasons", int64(m.reasons))
	writeInt("sched_p99_us_max", m.schedP99UsMax)
	writeInt("burst_est_s_min", m.burstEstSMin)
	b.WriteByte(',')
	writeString(&b, "burst_model", m.burstModel)
	writeInt("inflight_max", m.inflightMax)
	writeInt("admission_limit_min", m.admissionLimitMin)
	for i, name := range nodeStateCounterNames {
		b.WriteByte(',')
		writeUint64(&b, name, m.counts[i])
	}
	writeInt("gomaxprocs", int64(m.gomaxprocs))
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
