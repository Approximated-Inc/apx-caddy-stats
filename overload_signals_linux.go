//go:build linux

package apxstats

import "os"

func (procSignals) procStat() (cpuTimes, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	return parseProcStat(data)
}

func (procSignals) cgroupThrottledUsec() (uint64, bool) {
	data, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	if err != nil {
		return 0, false
	}
	return parseCgroupThrottled(data)
}

func (procSignals) uptime() (float64, bool) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	return parseUptime(data)
}
