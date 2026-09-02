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

// lbDecayed returns e's EWMA decayed toward 0 (optimistic) for however long
// it has sat unsampled as of at. This is the single definition of "what
// this upstream's score is right now" — both lbScore's read path and
// lbRecord's write path go through it, so a fold always blends the new
// sample against the same value a concurrent read would see, not a stale
// undecayed one.
func lbDecayed(e *lbEntry, at time.Time) float64 {
	idle := at.Sub(e.lastSeen)
	if idle <= 0 {
		return e.ewma
	}
	return e.ewma * math.Pow(0.5, float64(idle)/float64(lbDecayHalfLife))
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
		// A never-seen dial is the only event that grows the map, so it is
		// the natural moment to drop stale entries. New dials are rare in
		// steady state (config changes), so the O(n) sweep stays off the
		// per-request path.
		lbEvictLocked()
		lbEntries[dial] = &lbEntry{ewma: float64(d), lastSeen: lbNow()}
		return
	}
	now := lbNow()
	e.ewma = lbAlpha*float64(d) + (1-lbAlpha)*lbDecayed(e, now)
	e.lastSeen = now
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
	return lbDecayed(e, lbNow()), true
}

// lbEvict drops entries untouched for longer than lbEvictAfter so the map
// does not grow without bound as vhosts and upstreams come and go.
func lbEvict() {
	lbMu.Lock()
	defer lbMu.Unlock()
	lbEvictLocked()
}

// lbEvictLocked is lbEvict for callers already holding lbMu.
func lbEvictLocked() {
	cutoff := lbNow().Add(-lbEvictAfter)
	for dial, e := range lbEntries {
		if e.lastSeen.Before(cutoff) {
			delete(lbEntries, dial)
		}
	}
}
