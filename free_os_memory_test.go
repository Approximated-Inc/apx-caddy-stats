package apxstats

import (
	"sync"
	"testing"
	"time"
)

// callTimeout is generous so a loaded CI box can't fail the "did it fire"
// leg; the common case returns as soon as the call lands.
const freeOSMemCallTimeout = 2 * time.Second

// quietWindow is how long we watch for an unwanted second call. Short
// because a double-fire lands microseconds-to-milliseconds after the first.
const freeOSMemQuietWindow = 60 * time.Millisecond

// installFreeOSMemoryProbe swaps in a counting fn and returns its call
// channel. It resets the package-level debounce state on both ends so
// pending timers from a previous test can't bleed into this one (or this
// test's into the next).
func installFreeOSMemoryProbe(t *testing.T) chan struct{} {
	t.Helper()
	resetFreeOSMemoryState()
	calls := make(chan struct{}, 32)
	old := freeOSMemoryFn
	freeOSMemoryFn = func() {
		// Non-blocking: a stray timer must never park a runtime goroutine.
		select {
		case calls <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() {
		resetFreeOSMemoryState()
		freeOSMemoryFn = old
	})
	return calls
}

// resetFreeOSMemoryState cancels any pending debounce and invalidates any
// callback already in flight by bumping the generation.
func resetFreeOSMemoryState() {
	freeOSMemMu.Lock()
	if freeOSMemTimer != nil {
		freeOSMemTimer.Stop()
	}
	freeOSMemTimer = nil
	freeOSMemGen++
	freeOSMemMu.Unlock()
}

func awaitFreeOSMemoryCall(t *testing.T, calls <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-calls:
	case <-time.After(freeOSMemCallTimeout):
		t.Fatalf("%s: no FreeOSMemory call within %s", what, freeOSMemCallTimeout)
	}
}

func assertNoFreeOSMemoryCall(t *testing.T, calls <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-calls:
		t.Fatalf("%s: unexpected extra FreeOSMemory call", what)
	case <-time.After(freeOSMemQuietWindow):
	}
}

// A burst of schedules must collapse into exactly one call.
func TestScheduleFreeOSMemoryDebounces(t *testing.T) {
	calls := installFreeOSMemoryProbe(t)

	scheduleFreeOSMemory(20 * time.Millisecond)
	scheduleFreeOSMemory(20 * time.Millisecond) // resets the first timer
	scheduleFreeOSMemory(20 * time.Millisecond)

	awaitFreeOSMemoryCall(t, calls, "burst")
	assertNoFreeOSMemoryCall(t, calls, "burst")
}

// Two bursts separated by a completed call are two independent debounces:
// one call each, not one total and not three.
func TestScheduleFreeOSMemoryFiresOncePerBurst(t *testing.T) {
	calls := installFreeOSMemoryProbe(t)

	scheduleFreeOSMemory(10 * time.Millisecond)
	scheduleFreeOSMemory(10 * time.Millisecond)
	awaitFreeOSMemoryCall(t, calls, "first burst")
	assertNoFreeOSMemoryCall(t, calls, "first burst")

	// The first burst's timer has fired and cleared itself; a later Stop()
	// starts a fresh generation rather than being swallowed.
	scheduleFreeOSMemory(10 * time.Millisecond)
	awaitFreeOSMemoryCall(t, calls, "second burst")
	assertNoFreeOSMemoryCall(t, calls, "second burst")
}

// A reschedule that lands on (or just after) the previous timer's expiry
// gets false from Timer.Stop and cannot cancel it, so the superseded
// callback still runs — the generation check is what keeps it from calling
// FreeOSMemory a second time within the burst.
//
// The interleaving is forced, not raced: freeOSMemBeforeLockHook runs inside
// the first callback after it has fired but before it takes the mutex, which
// is exactly the window Stop() can no longer close. The reschedule there
// bumps the generation, so the first callback must find itself stale and the
// second burst owns the single call. Without the generation check the first
// callback calls fn immediately and the reschedule's timer calls it again
// 20ms later, inside the quiet window.
func TestScheduleFreeOSMemoryStaleTimerDoesNotDoubleFire(t *testing.T) {
	calls := installFreeOSMemoryProbe(t)

	var once sync.Once
	freeOSMemBeforeLockHook = func() {
		// Only the superseding schedule; its own callback must run normally.
		once.Do(func() { scheduleFreeOSMemory(20 * time.Millisecond) })
	}
	t.Cleanup(func() {
		resetFreeOSMemoryState() // orders against any in-flight callback
		freeOSMemBeforeLockHook = nil
	})

	scheduleFreeOSMemory(0)

	awaitFreeOSMemoryCall(t, calls, "stale-timer race")
	assertNoFreeOSMemoryCall(t, calls, "stale-timer race")
}
