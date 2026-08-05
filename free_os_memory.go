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
var (
	freeOSMemMu    sync.Mutex
	freeOSMemTimer *time.Timer
	freeOSMemoryFn = debug.FreeOSMemory // swapped in tests
)

func scheduleFreeOSMemory(d time.Duration) {
	freeOSMemMu.Lock()
	defer freeOSMemMu.Unlock()
	if freeOSMemTimer != nil {
		freeOSMemTimer.Stop()
	}
	fn := freeOSMemoryFn
	freeOSMemTimer = time.AfterFunc(d, fn)
}
