package apxstats

import (
	"compress/gzip"
	"errors"
	"io"
	"sync/atomic"
)

const (
	domainHealthResidentRecords = 8192
	domainHealthRawFrameBytes   = 4 << 20
	domainHealthGzipFrameBytes  = 2 << 20
)

// Credits cover live keys, detached snapshots and health rows in queued or
// in-flight bodies across all Caddy app generations. They bound cardinality,
// not literal Go RSS. Existing-key updates never touch this atomic counter.
var domainHealthCredits atomic.Int64
var domainHealthEncoding atomic.Bool

type domainHealthDropReason uint8

const (
	domainHealthDropCapacity domainHealthDropReason = iota
	domainHealthDropPressure
	domainHealthDropRetired
	domainHealthDropEncodeBusy
	domainHealthDropFrameLimit
	domainHealthDropEncodeError
	domainHealthDropQueue
	domainHealthDropDelivery
)

func countDomainHealthDrop(reason domainHealthDropReason, records int64) {
	if records <= 0 {
		return
	}
	if int(reason) >= len(metricDomainHealthDropCounters) {
		reason = domainHealthDropEncodeError
	}
	metricDomainHealthDropCounters[reason].Add(float64(records))
}

func reserveDomainHealthCredit() bool {
	for {
		current := domainHealthCredits.Load()
		if current >= domainHealthResidentRecords {
			return false
		}
		if domainHealthCredits.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

type domainHealthLease struct {
	records  int64
	released atomic.Bool
}

func (l *domainHealthLease) release() bool {
	if l == nil || !l.released.CompareAndSwap(false, true) {
		return false
	}
	domainHealthCredits.Add(-l.records)
	return true
}

func (l *domainHealthLease) drop(reason domainHealthDropReason) {
	if l.release() {
		countDomainHealthDrop(reason, l.records)
	}
}

type domainHealthSnapshot struct {
	rows  map[domainHealthKey]*domainHealthCounter
	lease *domainHealthLease
}

func (a *StatsApp) retireDomainHealth() {
	a.domainHealthRetired.Store(true)
	a.discardDomainHealth(domainHealthDropRetired)
}

func (a *StatsApp) discardDomainHealth(reason domainHealthDropReason) {
	_, records := a.detachDomainHealth()
	if records > 0 {
		domainHealthCredits.Add(-int64(records))
		countDomainHealthDrop(reason, int64(records))
	}
}

var errDomainHealthFrameLimit = errors.New("domain-health frame limit")

type domainHealthBuffer struct {
	data  []byte
	limit int
}

func (b *domainHealthBuffer) Len() int { return len(b.data) }
func (b *domainHealthBuffer) Bytes() []byte { return b.data }

func (b *domainHealthBuffer) reserve(n int) error {
	if n > b.limit-len(b.data) {
		return errDomainHealthFrameLimit
	}
	needed := len(b.data) + n
	if needed > cap(b.data) {
		capacity := min(b.limit, max(needed, max(512, 2*cap(b.data))))
		grown := make([]byte, len(b.data), capacity)
		copy(grown, b.data)
		b.data = grown
	}
	return nil
}

func (b *domainHealthBuffer) Write(p []byte) (int, error) {
	if err := b.reserve(len(p)); err != nil {
		return 0, err
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *domainHealthBuffer) WriteString(s string) (int, error) {
	if err := b.reserve(len(s)); err != nil {
		return 0, err
	}
	b.data = append(b.data, s...)
	return len(s), nil
}

// One permit covers preflight and the final health contribution to the
// existing single gzip stream. Busy encoders drop health rather than wait.
type domainHealthFrame struct {
	app         *StatsApp
	raw         []byte
	lease       *domainHealthLease
	encodedRows int
	gzipBytes   int
	finished    atomic.Bool
}

func (a *StatsApp) prepareDomainHealth(snapshot *domainHealthSnapshot, rawLimit, gzipLimit int) *domainHealthFrame {
	if snapshot == nil {
		return nil
	}
	if a.domainHealthRetired.Load() {
		snapshot.lease.drop(domainHealthDropRetired)
		return nil
	}
	if !domainHealthEncoding.CompareAndSwap(false, true) {
		snapshot.lease.drop(domainHealthDropEncodeBusy)
		return nil
	}
	frame := &domainHealthFrame{app: a, lease: snapshot.lease}
	failed := true
	defer func() {
		if failed {
			frame.finishEncoding()
		}
	}()
	if rawLimit <= 0 || gzipLimit <= 0 {
		frame.lease.drop(domainHealthDropFrameLimit)
		return nil
	}
	raw := &domainHealthBuffer{data: make([]byte, 0, min(rawLimit, int(snapshot.lease.records)*448)), limit: rawLimit}
	for key, counter := range snapshot.rows {
		if a.domainHealthRetired.Load() {
			frame.lease.drop(domainHealthDropRetired)
			return nil
		}
		if err := encodeDomainHealthRow(raw, a.ProxyServerIDValue, key, counter); err != nil {
			frame.lease.drop(domainHealthDropFrameLimit)
			return nil
		}
	}
	compressed := &domainHealthBuffer{data: make([]byte, 0, min(gzipLimit, int(snapshot.lease.records)*96)), limit: gzipLimit}
	gz := gzip.NewWriter(compressed)
	for offset := 0; offset < raw.Len(); {
		if a.domainHealthRetired.Load() {
			frame.lease.drop(domainHealthDropRetired)
			return nil
		}
		end := min(offset+32*1024, raw.Len())
		if _, err := gz.Write(raw.Bytes()[offset:end]); err != nil {
			frame.lease.drop(domainHealthDropFrameLimit)
			return nil
		}
		offset = end
	}
	if err := gz.Close(); err != nil {
		frame.lease.drop(domainHealthDropFrameLimit)
		return nil
	}
	frame.raw = raw.Bytes()
	frame.gzipBytes = compressed.Len()
	failed = false
	return frame
}

func (f *domainHealthFrame) writeTo(w io.Writer) error {
	if f == nil || f.finished.Load() || f.lease.released.Load() {
		return nil
	}
	if f.app.domainHealthRetired.Load() {
		f.lease.drop(domainHealthDropRetired)
		return nil
	}
	written, err := w.Write(f.raw)
	if err != nil {
		return err
	}
	if written != len(f.raw) {
		return io.ErrShortWrite
	}
	f.encodedRows = int(f.lease.records)
	return nil
}

func (f *domainHealthFrame) finishEncoding() {
	if f == nil || !f.finished.CompareAndSwap(false, true) {
		return
	}
	f.raw = nil
	domainHealthEncoding.Store(false)
}
