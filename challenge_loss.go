package apxstats

import (
	"compress/gzip"
	"sort"
	"strings"
	"sync"
)

// challengeLossMaxMinutes bounds the process-wide loss map.
const challengeLossMaxMinutes = 1440

type challengeLossKey struct {
	ps     uint32
	minute uint32
}

// challengeLossEntry is one lost minute for one cluster.
type challengeLossEntry struct {
	ps     uint32
	minute uint32
	count  uint64
}

// challengeLoss records the minutes for which challenge rows may be missing
// (a non-page key dropped past the reserve, or a batch that never arrived).
// The app turns each into a `challenge_loss` row and refuses to raise on a
// cluster with a loss in the window.
//
// It is process-wide, not per StatsApp: a Caddy reload stops the old instance,
// whose pending loss would otherwise be gone. Every instance adds here,
// whichever instance is live drains it on its next flush, and a retired
// instance whose delivery fails puts its minutes back for the replacement.
// Not covered: a process exit with an undelivered batch.
var challengeLoss = struct {
	mu sync.Mutex
	m  map[challengeLossKey]uint64
}{m: make(map[challengeLossKey]uint64)}

// addChallengeLoss records n lost rows for (ps, minute). At the bound the
// oldest minute of the same cluster is merged into a later one, never
// dropped: a marker only ever moves later, which keeps more windows
// unattributed, the safe direction.
func addChallengeLoss(ps, minute uint32, n uint64) {
	if n == 0 {
		return
	}
	challengeLoss.mu.Lock()
	defer challengeLoss.mu.Unlock()
	k := challengeLossKey{ps, minute}
	if _, ok := challengeLoss.m[k]; !ok && len(challengeLoss.m) >= challengeLossMaxMinutes {
		var oldest challengeLossKey
		found := false
		for ek := range challengeLoss.m {
			if ek.ps == ps && (!found || ek.minute < oldest.minute) {
				oldest, found = ek, true
			}
		}
		if found {
			if minute <= oldest.minute {
				challengeLoss.m[oldest] += n
				return
			}
			n += challengeLoss.m[oldest]
			delete(challengeLoss.m, oldest)
		}
	}
	challengeLoss.m[k] += n
}

// takeChallengeLoss removes and returns every pending loss entry, ordered.
func takeChallengeLoss() []challengeLossEntry {
	challengeLoss.mu.Lock()
	defer challengeLoss.mu.Unlock()
	if len(challengeLoss.m) == 0 {
		return nil
	}
	out := make([]challengeLossEntry, 0, len(challengeLoss.m))
	for k, c := range challengeLoss.m {
		out = append(out, challengeLossEntry{ps: k.ps, minute: k.minute, count: c})
	}
	challengeLoss.m = make(map[challengeLossKey]uint64)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ps != out[j].ps {
			return out[i].ps < out[j].ps
		}
		return out[i].minute < out[j].minute
	})
	return out
}

// challengeCarry is what a batch carried that must not be lost silently:
// the minutes of its non-page challenge rows, and the loss rows it shipped.
// If the batch does not arrive, both go back into the process-wide map.
type challengeCarry struct {
	minutes []challengeLossEntry
	losses  []challengeLossEntry
}

// fail returns the carry to the loss map after a drop or failed delivery.
// Nil-safe.
func (c *challengeCarry) fail() {
	if c == nil {
		return
	}
	for _, e := range c.minutes {
		addChallengeLoss(e.ps, e.minute, e.count)
	}
	for _, e := range c.losses {
		addChallengeLoss(e.ps, e.minute, e.count)
	}
	c.minutes, c.losses = nil, nil
}

// newChallengeCarry summarises a drained challenge snapshot plus the loss
// entries taken for the same batch. Returns nil when both are empty.
func newChallengeCarry(ps uint32, snap map[challengeAttemptKey]uint64, losses []challengeLossEntry) *challengeCarry {
	var minutes []challengeLossEntry
	for k, n := range snap {
		if isChallengePageOutcome(k.outcome) {
			continue
		}
		found := false
		for i := range minutes {
			if minutes[i].minute == k.tsMin {
				minutes[i].count += n
				found = true
				break
			}
		}
		if !found {
			minutes = append(minutes, challengeLossEntry{ps: ps, minute: k.tsMin, count: n})
		}
	}
	if len(minutes) == 0 && len(losses) == 0 {
		return nil
	}
	return &challengeCarry{minutes: minutes, losses: losses}
}

// encodeChallengeLossRow writes one `challenge_loss` NDJSON line:
//
//	{"_type":"challenge_loss","ts":"...","proxy_server_id":N,"lost_count":N}
//
// ts is the lost minute, not the flush minute.
func encodeChallengeLossRow(w *gzip.Writer, e challengeLossEntry) error {
	var b strings.Builder
	b.Grow(96)
	b.WriteByte('{')
	writeString(&b, "_type", "challenge_loss")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(e.minute))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", e.ps)
	b.WriteByte(',')
	writeUint64(&b, "lost_count", e.count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
