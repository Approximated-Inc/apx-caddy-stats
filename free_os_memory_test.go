package apxstats

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduleFreeOSMemoryDebounces(t *testing.T) {
	var calls atomic.Int32
	old := freeOSMemoryFn
	freeOSMemoryFn = func() { calls.Add(1) }
	defer func() { freeOSMemoryFn = old }()

	scheduleFreeOSMemory(30 * time.Millisecond)
	scheduleFreeOSMemory(30 * time.Millisecond) // resets the first timer
	time.Sleep(120 * time.Millisecond)

	if got := calls.Load(); got != 1 {
		t.Fatalf("want exactly 1 FreeOSMemory call, got %d", got)
	}
}
