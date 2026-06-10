//go:build linux

package apxstats

import (
	"os"

	"golang.org/x/sys/unix"
)

// cgroupMemMaxPath is the cgroup v2 memory limit for the current cgroup.
const cgroupMemMaxPath = "/sys/fs/cgroup/memory.max"

// detectTotalRAM returns the machine's usable RAM: the MIN of sysinfo(2)
// Totalram (the real machine size on Fly's Firecracker microVMs) and the
// cgroup v2 memory.max limit when one is set — belt-and-suspenders for
// any container model where the cgroup is tighter than the host.
func detectTotalRAM() (uint64, bool) {
	var best uint64
	var si unix.Sysinfo_t
	if err := unix.Sysinfo(&si); err == nil {
		if total := uint64(si.Totalram) * uint64(si.Unit); total > 0 {
			best = total
		}
	}
	if data, err := os.ReadFile(cgroupMemMaxPath); err == nil {
		if limit, ok := parseCgroupMemMax(data); ok && (best == 0 || limit < best) {
			best = limit
		}
	}
	return best, best > 0
}

// readProcessRSS returns the process's TRUE resident set size in bytes
// from /proc/self/statm (field 2 = resident pages). RSS — not Go heap —
// is what the OOM killer scores: under flood the growth is off-heap
// (goroutine stacks, mmap'd CRS/geoip pages) that runtime.MemStats can't
// see. The read is a ~µs pseudo-file read with no STW.
func readProcessRSS() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	return parseStatmRSS(data, os.Getpagesize())
}
