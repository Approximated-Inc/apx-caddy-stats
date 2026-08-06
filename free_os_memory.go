package apxstats

import (
	"runtime/debug"
	"sync"
	"time"
)

// Go returns freed pages to the OS lazily (MADV_FREE), so RSS stays inflated
// after a config swap frees the old WAF/ruleset. One explicit FreeOSMemory
// shortly after teardown drops it. Debounced: rapid successive reloads reset
// the timer instead of stacking calls.
//
// freeOSMemGen makes the debounce single-shot per burst. Timer.Stop reports
// false once the callback has fired or started running, so a reschedule that
// lands on the expiry instant cannot cancel its predecessor — without the
// generation check both would call FreeOSMemory.
var (
	freeOSMemMu    sync.Mutex
	freeOSMemTimer *time.Timer
	freeOSMemGen   uint64
	freeOSMemoryFn = debug.FreeOSMemory // swapped in tests
)

func scheduleFreeOSMemory(d time.Duration) {
	freeOSMemMu.Lock()
	defer freeOSMemMu.Unlock()
	if freeOSMemTimer != nil {
		freeOSMemTimer.Stop()
	}
	freeOSMemGen++
	gen := freeOSMemGen
	fn := freeOSMemoryFn
	freeOSMemTimer = time.AfterFunc(d, func() {
		freeOSMemMu.Lock()
		stale := gen != freeOSMemGen
		if !stale {
			freeOSMemTimer = nil
		}
		freeOSMemMu.Unlock()
		if stale {
			// A later schedule superseded this timer after it had already
			// fired; that schedule owns the call.
			return
		}
		// Called without the mutex held: FreeOSMemory stops the world and
		// can take real time, and schedulers must not block behind it.
		fn()
	})
}
