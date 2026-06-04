package apxstats

import "sync"

// requestEventRecorder accumulates raw request_event rows (one per SERVED
// request — the served-only filter is applied at the handler, not here)
// into a flat append buffer per window, with a per-window
// sample-under-load guard plus a hard cap.
//
// Sample-under-load (deterministic): seen counts emits considered this
// window. While seen < threshold (or threshold<=0) every row is kept with
// SampleRate=1. Once seen >= threshold the recorder samples: the current
// factor n := seen/threshold + 1, and the row is kept only when
// seen % n == 0, stamped SampleRate=n. The factor grows as the window
// fills, so a busier window samples harder.
//
// Cap: once len(rows) reaches maxRows, kept rows are dropped and counted
// in overflow. drain swaps out the rows and resets seen + overflow for the
// next window.
type requestEventRecorder struct {
	mu        sync.Mutex
	rows      []requestEventRow
	maxRows   int    // cap; drop + overflow past it
	threshold int    // sample-under-load: emits/window above this -> sample
	seen      int    // emits considered this window
	overflow  uint64 // kept rows dropped at cap this window
}

// newRequestEventRecorder builds a recorder capped at maxRows rows/window
// that begins sampling once threshold emits have been seen in a window.
// A threshold <= 0 disables sampling (every row kept, SampleRate=1).
func newRequestEventRecorder(maxRows, threshold int) *requestEventRecorder {
	return &requestEventRecorder{maxRows: maxRows, threshold: threshold}
}

// record is called once per served request. The caller has already applied
// the served-only filter and built row WITHOUT SampleRate; record computes
// the sample decision, stamps SampleRate on kept rows, and appends (or
// counts overflow at the cap).
func (r *requestEventRecorder) record(row requestEventRow) {
	r.mu.Lock()
	defer r.mu.Unlock()

	keep := true
	rate := uint16(1)
	if r.threshold > 0 && r.seen >= r.threshold {
		n := r.seen/r.threshold + 1
		if r.seen%n == 0 {
			rate = uint16(n)
		} else {
			keep = false
		}
	}
	r.seen++

	if !keep {
		return
	}
	if len(r.rows) >= r.maxRows {
		r.overflow++
		return
	}
	row.SampleRate = rate
	r.rows = append(r.rows, row)
}

// drain swaps out the accumulated rows and resets the window (seen and
// overflow back to zero), returning the rows plus this window's overflow.
func (r *requestEventRecorder) drain() ([]requestEventRow, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rows := r.rows
	overflow := r.overflow
	r.rows = nil
	r.seen = 0
	r.overflow = 0
	return rows, overflow
}
