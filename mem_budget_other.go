//go:build !linux

package apxstats

// Non-Linux (dev) builds have no sysinfo/cgroup/procfs: detection
// reports failure so the governor falls back to fallbackTotalRAMBytes,
// and RSS reads degrade to the share budget alone. The production fleet
// is Linux-only.

func detectTotalRAM() (uint64, bool) { return 0, false }

func readProcessRSS() (uint64, bool) { return 0, false }
