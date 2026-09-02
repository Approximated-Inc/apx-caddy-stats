package apxstats

import (
	"math"
	"sync"
	"time"
)

// Passive latency measurement for the apx_latency upstream selection
// policy. Every identifier here is lb-prefixed: this package is shared
// with the stats, trace and challenge modules.

// lbAlpha is the weight given to each new sample when folding it into an
// upstream's exponentially weighted moving average.
const lbAlpha = 0.2

// lbDecayHalfLife is how long an unsampled upstream takes to have its
// score halved. Decay pulls idle upstreams back toward optimistic so they
// get re-explored, instead of being exiled forever by one bad sample.
const lbDecayHalfLife = 30 * time.Second

// lbEvictAfter is how long an unsampled entry is retained before removal.
const lbEvictAfter = 10 * time.Minute

type lbEntry struct {
	ewma     float64 // nanoseconds
	lastSeen time.Time
}

// State is package-level on purpose. Caddy re-provisions every module on a
// config reload and clusters regenerate config often; keeping latency
// history out of module state means it survives a reload, the same way
// Caddy preserves its own upstream host state across reloads.
var (
	lbMu      sync.Mutex
	lbEntries = map[string]*lbEntry{}
	lbNow     = time.Now
)

// lbReset clears all state. Test seam only.
func lbReset() {
	lbMu.Lock()
	defer lbMu.Unlock()
	lbEntries = map[string]*lbEntry{}
}

// lbRecord folds one observed upstream round-trip into its EWMA.
func lbRecord(dial string, d time.Duration) {
	if dial == "" || d <= 0 {
		return
	}
	lbMu.Lock()
	defer lbMu.Unlock()

	e, ok := lbEntries[dial]
	if !ok {
		lbEntries[dial] = &lbEntry{ewma: float64(d), lastSeen: lbNow()}
		return
	}
	e.ewma = lbAlpha*float64(d) + (1-lbAlpha)*e.ewma
	e.lastSeen = lbNow()
}

// lbScore returns the decayed EWMA in nanoseconds and whether this
// upstream has ever been sampled. An unsampled upstream scores 0, the most
// optimistic value, so a cold pool falls through to config order and a
// newly added upstream gets explored immediately.
func lbScore(dial string) (float64, bool) {
	lbMu.Lock()
	defer lbMu.Unlock()

	e, ok := lbEntries[dial]
	if !ok {
		return 0, false
	}
	idle := lbNow().Sub(e.lastSeen)
	if idle <= 0 {
		return e.ewma, true
	}
	return e.ewma * math.Pow(0.5, float64(idle)/float64(lbDecayHalfLife)), true
}

// lbEvict drops entries untouched for longer than lbEvictAfter so the map
// does not grow without bound as vhosts and upstreams come and go.
func lbEvict() {
	lbMu.Lock()
	defer lbMu.Unlock()

	cutoff := lbNow().Add(-lbEvictAfter)
	for dial, e := range lbEntries {
		if e.lastSeen.Before(cutoff) {
			delete(lbEntries, dial)
		}
	}
}
