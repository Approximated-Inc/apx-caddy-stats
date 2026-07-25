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

	// gov, when set, byte-bounds the buffer: every kept row reserves its
	// approximate size via tryReserve (reject -> drop + overflow) and the
	// governor's pressure raises the minimum sample factor. nil =
	// ungoverned (tests).
	gov           *memGovernor
	reservedBytes int // governor bytes reserved this window; released at drain
}

// newRequestEventRecorder builds a recorder capped at maxRows rows/window
// that begins sampling once threshold emits have been seen in a window.
// A threshold <= 0 disables load-based sampling (every row kept,
// SampleRate=1) — but a non-nil gov can still force sampling and drops
// under memory pressure.
func newRequestEventRecorder(maxRows, threshold int, gov *memGovernor) *requestEventRecorder {
	return &requestEventRecorder{maxRows: maxRows, threshold: threshold, gov: gov}
}

// requestEventRowFixedBytes over-approximates the in-memory fixed cost of
// one buffered row (unsafe.Sizeof(requestEventRow{}) plus append slack).
// Pinned by TestRowFixedBytesCoverStructSizes against the real Sizeof.
// Bumped from 192 when the mode_v2 fields (TsUnixMs/MachineID/MachineSeq/
// Disposition/Host/V2) were added.
const requestEventRowFixedBytes = 320

// requestEventRowBytes approximates the resident bytes one buffered row
// holds: the fixed struct size plus every string field's backing bytes.
func requestEventRowBytes(row *requestEventRow) int {
	return requestEventRowFixedBytes +
		len(row.ClientIP) + len(row.ForwardedIP) + len(row.FrontProxy) +
		len(row.Method) + len(row.Path) + len(row.PathBucket) +
		len(row.HTTPVersion) + len(row.UA) + len(row.Origin) +
		len(row.MachineID) + len(row.Disposition) + len(row.Host)
}

// record is called once per served request. The caller has already applied
// the served-only filter and built row WITHOUT SampleRate; record computes
// the sample decision, stamps SampleRate on kept rows, and appends (or
// counts overflow at the row cap / governor byte budget).
//
// The sample factor is the MAX of the seen-based load factor and the
// governor's pressure-driven floor: as memory pressure rises past
// pressureSampleStart the recorder sheds rows progressively (a fair
// downsample Phoenix can upscale via SampleRate) rather than running
// into the hard tryReserve cliff. request_events is already a sampled
// substrate that detection never trusts for auto-blocks, so dropping
// long-tail rows under pressure is acceptable.
func (r *requestEventRecorder) record(row requestEventRow) {
	r.mu.Lock()
	defer r.mu.Unlock()

	factor := 1
	if r.threshold > 0 && r.seen >= r.threshold {
		factor = r.seen/r.threshold + 1
	}
	if r.gov != nil {
		if pf := pressureSampleFloor(r.gov.pressure()); pf > factor {
			factor = pf
		}
	}

	keep := true
	rate := uint16(1)
	if factor > 1 {
		if r.seen%factor == 0 {
			rate = uint16(factor)
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
	// Hard backstop: the row's bytes must fit the governed budget.
	if r.gov != nil {
		n := requestEventRowBytes(&row)
		if !r.gov.tryReserve(n) {
			r.overflow++
			return
		}
		r.reservedBytes += n
	}
	row.SampleRate = rate
	r.rows = append(r.rows, row)
}

// drain swaps out the accumulated rows, releases this window's governor
// reservation, and resets the window (seen and overflow back to zero),
// returning the rows plus this window's overflow.
func (r *requestEventRecorder) drain() ([]requestEventRow, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rows := r.rows
	overflow := r.overflow
	if r.gov != nil && r.reservedBytes > 0 {
		r.gov.release(r.reservedBytes)
	}
	r.reservedBytes = 0
	r.rows = nil
	r.seen = 0
	r.overflow = 0
	return rows, overflow
}
