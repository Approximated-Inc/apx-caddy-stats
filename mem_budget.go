package apxstats

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// The analytics buffers must never OOM the machine: on a 256MB Fly
// machine the drainable byte-heavy buffers (request_events rows + coraza
// detection events) could otherwise sum past available RAM and the OOM
// killer would take down the Caddy process — and every co-tenant vhost
// on it. The memGovernor bounds those buffers by BYTES (row counts don't
// bound RAM — rows vary ~5x in width), self-sized to the machine's
// ACTUAL RAM detected at runtime: the autoscaler resizes machines
// per-machine, so config-gen can't know the size.

const (
	// bufferShareFraction is the slice of total RAM the governed buffers
	// may hold combined — the "leave 60% for everything else" knob.
	bufferShareFraction = 0.40
	// rssCeilingFraction is the line total process RSS must not cross —
	// the OOM-prevention backstop under which baseline + buffers +
	// off-heap (goroutine stacks, mmap'd CRS/geoip pages) must all fit.
	rssCeilingFraction = 0.80

	// minTotalRAMBytes floors a successful-but-implausible detection so
	// a bad reading can't produce a tiny/zero budget. 128MB.
	minTotalRAMBytes = 128 << 20
	// fallbackTotalRAMBytes is assumed when detection fails entirely —
	// the smallest machine in the fleet. 256MB.
	fallbackTotalRAMBytes = 256 << 20

	// rssRefreshInterval is how often the cached RSS reading refreshes.
	// One ~µs procfs read per second; the hot path only loads the cache.
	rssRefreshInterval = time.Second
	// rssRefreshPressureInterval replaces rssRefreshInterval while
	// pressure() is past pressureSampleStart: near a limit, the ~1s cache
	// lag is the window in which an extreme flood could cross the ceiling
	// undetected, and the extra ~µs statm reads only happen then.
	rssRefreshPressureInterval = 150 * time.Millisecond
)

// Pressure-driven sample floor: as governor pressure rises past
// pressureSampleStart, the request_events recorder raises its MINIMUM
// sample factor toward pressureSampleMaxFactor at pressure 1.0 —
// shedding rows progressively (a fair downsample) instead of hitting
// the hard tryReserve cliff.
const (
	pressureSampleStart     = 0.70
	pressureSampleMaxFactor = 16
)

// pressureSampleFloor maps a 0..1 governor pressure to a minimum
// sampling factor: 1 (no floor) at or below pressureSampleStart, rising
// linearly to pressureSampleMaxFactor at pressure >= 1.0.
func pressureSampleFloor(p float64) int {
	if p <= pressureSampleStart {
		return 1
	}
	span := (p - pressureSampleStart) / (1 - pressureSampleStart)
	if span > 1 {
		span = 1
	}
	return 1 + int(span*float64(pressureSampleMaxFactor-1)+0.5)
}

// memGovernor enforces two limits over the governed buffers:
//
//   - shareBudget: a fast local byte tally (bufferBytes) of what the
//     governed buffers currently hold. Catches sub-second bursts between
//     RSS refreshes.
//   - rssCeiling: TRUE process RSS (from /proc/self/statm, cached every
//     rssRefreshInterval) must stay under this line. The global backstop
//     accounting for ALL memory — heap, goroutine stacks, mmap'd pages —
//     which is what the OOM killer scores. runtime.MemStats.HeapInuse
//     can't see the off-heap growth a flood produces, so we don't use it.
//
// One instance per StatsApp, built at Provision and shared by the
// request_events recorder and the coraza detection slice.
type memGovernor struct {
	totalRAM    uint64
	shareBudget uint64 // bufferShareFraction * totalRAM
	rssCeiling  uint64 // rssCeilingFraction * totalRAM
	baselineRSS uint64 // RSS at construction; pressure() rescales above it

	bufferBytes atomic.Int64  // bytes currently reserved by governed buffers
	cachedRSS   atomic.Uint64 // refreshed every rssRefreshInterval

	readRSS     func() (uint64, bool)
	logger      *zap.Logger
	rssWarnOnce sync.Once
}

// newMemGovernor builds a governor for a machine with totalRAM bytes.
// readRSS supplies the true process RSS (readProcessRSS in production;
// stubs in tests). It is read once here for the baseline and then by
// refreshLoop.
func newMemGovernor(totalRAM uint64, readRSS func() (uint64, bool), logger *zap.Logger) *memGovernor {
	g := &memGovernor{
		totalRAM:    totalRAM,
		shareBudget: uint64(bufferShareFraction * float64(totalRAM)),
		rssCeiling:  uint64(rssCeilingFraction * float64(totalRAM)),
		readRSS:     readRSS,
		logger:      logger,
	}
	g.refreshRSS()
	g.baselineRSS = g.cachedRSS.Load()
	return g
}

// refreshRSS reads true process RSS once and caches it atomically. On
// read failure (no procfs) it degrades gracefully: RSS is treated as 0
// so the share budget alone bounds the buffers; logged once.
func (g *memGovernor) refreshRSS() {
	if g.readRSS != nil {
		if rss, ok := g.readRSS(); ok {
			g.cachedRSS.Store(rss)
			return
		}
	}
	g.cachedRSS.Store(0)
	g.rssWarnOnce.Do(func() {
		if g.logger != nil {
			g.logger.Warn("apx_stats: process RSS unreadable — memory governor relies on the buffer share budget alone")
		}
	})
}

// refreshLoop refreshes the cached RSS on an adaptive cadence (see
// nextRefreshInterval) until stop closes. Driven by StatsApp.Start on
// the app's WaitGroup.
func (g *memGovernor) refreshLoop(stop <-chan struct{}) {
	t := time.NewTimer(g.nextRefreshInterval())
	defer t.Stop()
	for {
		select {
		case <-t.C:
			g.refreshRSS()
			t.Reset(g.nextRefreshInterval())
		case <-stop:
			return
		}
	}
}

// nextRefreshInterval picks the delay before the next RSS read: the
// normal ~1s cadence, tightened to rssRefreshPressureInterval while the
// governor is under pressure.
func (g *memGovernor) nextRefreshInterval() time.Duration {
	if g.pressure() > pressureSampleStart {
		return rssRefreshPressureInterval
	}
	return rssRefreshInterval
}

// tryReserve reserves n buffer bytes, returning false (caller drops the
// row and counts overflow) when total process RSS is over the ceiling OR
// the reservation would push the governed buffers past the share budget.
// Hot path: one atomic load + one CAS-add — negligible next to request
// handling.
func (g *memGovernor) tryReserve(n int) bool {
	if n <= 0 {
		return true
	}
	if g.cachedRSS.Load() > g.rssCeiling {
		return false
	}
	nn := int64(n)
	budget := int64(g.shareBudget)
	for {
		cur := g.bufferBytes.Load()
		if cur+nn > budget {
			return false
		}
		if g.bufferBytes.CompareAndSwap(cur, cur+nn) {
			return true
		}
	}
}

// release returns n previously reserved bytes to the budget — called
// when a buffer drains its accumulated bytes for the window. Clamps at
// zero defensively (an over-release indicates an accounting bug).
func (g *memGovernor) release(n int) {
	if n <= 0 {
		return
	}
	if v := g.bufferBytes.Add(-int64(n)); v < 0 {
		g.bufferBytes.CompareAndSwap(v, 0)
	}
}

// pressure returns a 0..1-ish signal that rises as either guard
// approaches its limit: the max of buffer-share utilization and RSS
// growth above the construction baseline toward the ceiling.
func (g *memGovernor) pressure() float64 {
	p := 0.0
	if g.shareBudget > 0 {
		p = float64(g.bufferBytes.Load()) / float64(g.shareBudget)
		if p < 0 {
			p = 0
		}
	}
	if rss := g.cachedRSS.Load(); rss > g.baselineRSS {
		denom := float64(g.rssCeiling) - float64(g.baselineRSS)
		if denom <= 0 {
			return max(p, 1)
		}
		p = max(p, (float64(rss)-float64(g.baselineRSS))/denom)
	}
	return p
}

// clampTotalRAM applies the floor/fallback policy to a detectTotalRAM
// result: detection failure assumes the smallest fleet machine; an
// implausibly small success is floored so the budgets can't collapse.
func clampTotalRAM(detected uint64, ok bool) uint64 {
	if !ok || detected == 0 {
		return fallbackTotalRAMBytes
	}
	if detected < minTotalRAMBytes {
		return minTotalRAMBytes
	}
	return detected
}

// parseStatmRSS extracts resident bytes from /proc/self/statm content
// (field 2 = resident pages × page size). Pure for portability of tests;
// the file read lives in mem_budget_linux.go.
func parseStatmRSS(data []byte, pageSize int) (uint64, bool) {
	fields := strings.Fields(string(data))
	if len(fields) < 2 || pageSize <= 0 {
		return 0, false
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(pageSize), true
}

// parseCgroupMemMax parses cgroup v2 memory.max content: a byte count,
// or the literal "max" (no limit) which reports !ok.
func parseCgroupMemMax(data []byte) (uint64, bool) {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}
