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

	// mode_v2: served rows bypass the seen-threshold sampler entirely
	// (unsampled) while non-served (blocked/rate-limited/challenge) rows use
	// blockedThreshold with their own seenBlocked window counter. The
	// governor's pressure floor + the row cap still apply to both.
	modeV2           bool
	blockedThreshold int
	seenBlocked      int
}

// newRequestEventRecorder builds a recorder capped at maxRows rows/window
// that begins sampling once threshold emits have been seen in a window.
// A threshold <= 0 disables load-based sampling (every row kept,
// SampleRate=1) — but a non-nil gov can still force sampling and drops
// under memory pressure.
func newRequestEventRecorder(maxRows, threshold int, gov *memGovernor) *requestEventRecorder {
	return &requestEventRecorder{maxRows: maxRows, threshold: threshold, gov: gov}
}

// newRequestEventRecorderV2 builds a mode_v2 recorder: served rows are kept
// unsampled (governor + cap still bound memory), non-served rows sample
// once seenBlocked passes blockedThreshold in a window. A blockedThreshold
// <= 0 disables load-based sampling for non-served rows too.
func newRequestEventRecorderV2(maxRows, blockedThreshold int, gov *memGovernor) *requestEventRecorder {
	return &requestEventRecorder{maxRows: maxRows, blockedThreshold: blockedThreshold, gov: gov, modeV2: true}
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

// record is called once per request the handler decides to log. The caller
// builds row WITHOUT SampleRate; record computes the sample decision (in
// mode_v2, recordV2Locked splits served vs. non-served internally — no
// served-only filter is applied by the caller), stamps SampleRate on kept
// rows, and appends (or counts overflow at the row cap / governor byte
// budget).
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

	if r.modeV2 {
		r.recordV2Locked(row)
		return
	}

	// Legacy: single seen-threshold sampler over every (served-only) row.
	factor := 1
	if r.threshold > 0 && r.seen >= r.threshold {
		factor = r.seen/r.threshold + 1
	}
	if r.gov != nil {
		if pf := pressureSampleFloor(r.gov.pressure()); pf > factor {
			factor = pf
		}
	}
	keep, rate := sampleDecision(r.seen, factor)
	r.seen++
	if keep {
		r.appendLocked(row, rate)
	}
}

// recordV2Locked applies disposition-aware sampling. Caller holds r.mu.
func (r *requestEventRecorder) recordV2Locked(row requestEventRow) {
	if row.Disposition == dispServed {
		// Served: UNSAMPLED by threshold. Only the governor's pressure floor
		// can force sampling under memory pressure; the row cap still binds.
		factor := 1
		if r.gov != nil {
			if pf := pressureSampleFloor(r.gov.pressure()); pf > factor {
				factor = pf
			}
		}
		keep, rate := sampleDecision(r.seen, factor)
		r.seen++
		if keep {
			r.appendLocked(row, rate)
		}
		return
	}

	// Non-served (blocked / rate-limited / challenge): own threshold + own
	// window counter, with the governor floor as a lower bound.
	factor := 1
	if r.blockedThreshold > 0 && r.seenBlocked >= r.blockedThreshold {
		factor = r.seenBlocked/r.blockedThreshold + 1
	}
	if r.gov != nil {
		if pf := pressureSampleFloor(r.gov.pressure()); pf > factor {
			factor = pf
		}
	}
	keep, rate := sampleDecision(r.seenBlocked, factor)
	r.seenBlocked++
	if keep {
		r.appendLocked(row, rate)
	}
}

// sampleDecision applies the deterministic 1-in-factor keep rule for the
// given per-window seen count. factor<=1 keeps every row at SampleRate=1.
func sampleDecision(seen, factor int) (keep bool, rate uint16) {
	if factor <= 1 {
		return true, 1
	}
	if seen%factor == 0 {
		return true, uint16(factor)
	}
	return false, 0
}

// appendLocked stamps SampleRate and appends row, honoring the row cap and
// the governor byte budget. Caller holds r.mu.
func (r *requestEventRecorder) appendLocked(row requestEventRow, rate uint16) {
	if len(r.rows) >= r.maxRows {
		r.overflow++
		return
	}
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
	r.seenBlocked = 0
	r.overflow = 0
	return rows, overflow
}
