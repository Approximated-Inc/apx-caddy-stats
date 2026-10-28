package apxstats

import (
	"bytes"
	"runtime/metrics"
	"strconv"
	"time"
)

// userHZ is the kernel's USER_HZ, fixed at 100 on every Linux ABI we run.
const userHZ = 100

// overloadSignals is the sampler's input. procSignals reads procfs and the
// Go runtime; tests inject fakes.
type overloadSignals interface {
	procStat() (cpuTimes, bool)
	cgroupThrottledUsec() (uint64, bool)
	uptime() (float64, bool)
	schedHistogram() (counts []uint64, buckets []float64, ok bool)
}

// cpuTimes is the aggregate "cpu" line of /proc/stat, in USER_HZ ticks.
type cpuTimes struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func (c cpuTimes) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

func (c cpuTimes) busy() uint64 { return c.user + c.nice + c.system + c.irq + c.softirq }

// parseProcStat parses the first ("cpu ") line of /proc/stat.
func parseProcStat(data []byte) (cpuTimes, bool) {
	line := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		line = data[:i]
	}
	f := bytes.Fields(line)
	if len(f) < 9 || string(f[0]) != "cpu" {
		return cpuTimes{}, false
	}
	var v [8]uint64
	for i := range v {
		n, err := strconv.ParseUint(string(f[i+1]), 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		v[i] = n
	}
	return cpuTimes{v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]}, true
}

// stealAndBusy returns the steal share of all CPU time in ‰ and busy cores
// (user+nice+system+irq+softirq, excluding steal and iowait) between two
// samples dt seconds apart. Inside a Fly shared VM, throttling shows as
// steal; cgroup cpu.stat stays 0.
func stealAndBusy(prev, cur cpuTimes, dt float64) (stealPermille int, busyCores float64, ok bool) {
	dTotal := cur.total() - prev.total()
	if cur.total() < prev.total() || dTotal == 0 || dt <= 0 {
		return 0, 0, false
	}
	dSteal := cur.steal - prev.steal
	if cur.steal < prev.steal {
		dSteal = 0
	}
	dBusy := cur.busy() - prev.busy()
	if cur.busy() < prev.busy() {
		dBusy = 0
	}
	return int(dSteal * 1000 / dTotal), float64(dBusy) / userHZ / dt, true
}

// parseCgroupThrottled reads throttled_usec from cgroup v2 cpu.stat.
func parseCgroupThrottled(data []byte) (uint64, bool) {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		f := bytes.Fields(line)
		if len(f) == 2 && string(f[0]) == "throttled_usec" {
			n, err := strconv.ParseUint(string(f[1]), 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// parseUptime reads the first field of /proc/uptime.
func parseUptime(data []byte) (float64, bool) {
	f := bytes.Fields(data)
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(string(f[0]), 64)
	return v, err == nil
}

const schedLatencyMetric = "/sched/latencies:seconds"

type procSignals struct{}

func (procSignals) schedHistogram() ([]uint64, []float64, bool) {
	s := []metrics.Sample{{Name: schedLatencyMetric}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindFloat64Histogram {
		return nil, nil, false
	}
	h := s[0].Value.Float64Histogram()
	counts := make([]uint64, len(h.Counts))
	copy(counts, h.Counts)
	return counts, h.Buckets, true
}

// schedWindow keeps the last 11 cumulative histograms so push can return
// the p99 of the delta over 10 samples (10 s at the 1 s interval).
type schedWindow struct{ hist [][]uint64 }

func (w *schedWindow) push(counts []uint64, buckets []float64) time.Duration {
	w.hist = append(w.hist, counts)
	if len(w.hist) > 11 {
		w.hist = w.hist[1:]
	}
	if len(w.hist) < 2 {
		return 0
	}
	return schedP99(w.hist[0], counts, buckets)
}

// schedP99 returns the 99th percentile of the delta between two cumulative
// runtime/metrics histograms, as the upper bound of its bucket (the lower
// bound for the +Inf bucket). Zero when nothing ran.
func schedP99(prev, cur []uint64, buckets []float64) time.Duration {
	if len(prev) != len(cur) || len(buckets) != len(cur)+1 {
		return 0
	}
	var total uint64
	delta := make([]uint64, len(cur))
	for i := range cur {
		if cur[i] >= prev[i] {
			delta[i] = cur[i] - prev[i]
		}
		total += delta[i]
	}
	if total == 0 {
		return 0
	}
	target := (total*99 + 99) / 100 // ceil(0.99 × total)
	var seen uint64
	for i, d := range delta {
		seen += d
		if seen >= target {
			upper := buckets[i+1]
			if upper > 1e9 { // +Inf
				upper = buckets[i]
			}
			return time.Duration(upper * float64(time.Second))
		}
	}
	return 0
}
