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

	// Test-only: runs at the top of the timer callback, before it takes the
	// mutex, so a test can deterministically slip a reschedule into that
	// window and force the stale branch. Always nil in production; the nil
	// check costs nothing on a path that runs once per config reload.
	freeOSMemBeforeLockHook func()
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
		if hook := freeOSMemBeforeLockHook; hook != nil {
			hook()
		}
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
