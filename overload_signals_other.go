//go:build !linux

package apxstats

// Non-Linux (dev) builds have no procfs: throttle and burst signals are
// unknown, so only scheduler latency can raise the level.

func (procSignals) procStat() (cpuTimes, bool) { return cpuTimes{}, false }

func (procSignals) cgroupThrottledUsec() (uint64, bool) { return 0, false }

func (procSignals) uptime() (float64, bool) { return 0, false }
