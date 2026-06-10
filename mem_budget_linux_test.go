//go:build linux

package apxstats

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// These run only on Linux (in CI / a container) — the dev loop on macOS
// covers the pure parse/clamp logic; these verify the real procfs +
// sysinfo + cgroup reads.

func TestDetectTotalRAM_Linux(t *testing.T) {
	total, ok := detectTotalRAM()
	require.True(t, ok, "sysinfo should always be readable on Linux")
	require.Greater(t, total, uint64(16<<20), "implausibly small total RAM")
	t.Logf("detectTotalRAM = %d bytes (%.1f MB)", total, float64(total)/(1<<20))
}

func TestReadProcessRSS_Linux(t *testing.T) {
	rss, ok := readProcessRSS()
	require.True(t, ok, "/proc/self/statm should always be readable on Linux")
	require.Greater(t, rss, uint64(1<<20), "a running test binary resides in more than 1MB")
	total, _ := detectTotalRAM()
	require.Less(t, rss, total*2, "RSS wildly larger than machine RAM means the parse is wrong")
	t.Logf("readProcessRSS = %d bytes (%.1f MB)", rss, float64(rss)/(1<<20))
}

// BenchmarkReadProcessRSS pins the cost claim for the 1s refresh loop:
// one read should be on the order of a microsecond (pseudo-file read, no
// STW), so polling at 1Hz is noise.
func BenchmarkReadProcessRSS(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, ok := readProcessRSS(); !ok {
			b.Fatal("readProcessRSS failed")
		}
	}
}
