package apxstats

import (
	"compress/gzip"
	"strings"
)

// challengeAttemptKey is the natural identity of an aggregated
// challenge_attempt counter row. Like L4SniKey, ProxyServerID is global
// per Caddy process (stamped at encode time) so it's not part of the
// key. tsMin is the minute the outcome happened (stamped at record time,
// as the L4 SNI track does), not the flush minute, so a failure from
// before a cutoff cannot land in the first bucket after it. A served
// challenge is terminal (the apx_challenge handler returns without calling next), so
// the per-vhost vars handler never runs and vhost_id is unset — the
// dimension is therefore the lowercased Host header, NOT vhost_id.
type challengeAttemptKey struct {
	vhost   string // lowercased Host header, port stripped
	ip      string // security client IP (PROXY-decoded RemoteAddr)
	outcome string // passed | passed_fallback | passed_recently, issued | failed, or a composed value (challengeReasonOutcomes)
	source  string // one of challengeSources, or "" when the challenge plugin sets no source var
	tsMin   uint32 // unix minute the outcome was recorded
}

// challengeMaxKeys caps distinct keys per flush window for page outcomes
// (issued_*, not_shown_*). A count cap (not the byte governor) is enough
// here: rows are tiny and bounded-width, so 50K keys is a few MB worst case.
// New page keys past the cap are dropped silently (challengeOverflow +
// metric): losing a page only undercounts ignored, the lenient direction.
// Existing keys keep counting.
const challengeMaxKeys = 50_000

// challengeReserveKeys is extra room for every other outcome (passes and all
// failed_*), which either clear an IP or erase ignored pages. A drop past the
// reserve marks the minute in challengeLoss.
const challengeReserveKeys = 5_000

// isChallengePageOutcome reports the outcomes whose loss is harmless.
func isChallengePageOutcome(outcome string) bool {
	return strings.HasPrefix(outcome, "issued") || strings.HasPrefix(outcome, "not_shown_")
}

// challengeVhostMaxBytes bounds the vhost key width: the Host header is
// attacker-supplied and unbounded on the wire, while real hostnames cap
// at 253 bytes (DNS). Keeps the "rows are tiny and bounded-width" premise
// of the count cap above true. Mirrors corazaRequestHostMaxBytes.
const challengeVhostMaxBytes = 255

// encodeChallengeAttemptRow writes one NDJSON line for an aggregated
// challenge_attempt counter entry. Format (field order is part of the
// Phoenix contract — `_type` MUST be first, `source` sits between `outcome`
// and `attempt_count`):
//
//	{"_type":"challenge_attempt","ts":"...","proxy_server_id":N,"vhost":"...","ip":"...","outcome":"...","source":"...","attempt_count":N}
//
// source is always written, "" when the var was absent, so its presence
// tells the app the row came from a stats build that records request
// minutes. ts is minute-precision RFC3339 (formatTs) of the minute the
// outcome was recorded (k.tsMin). Matches the `normalize_challenge_attempt_row/1` clause in the
// Phoenix analytics ingest controller, which downcases vhost,
// canonicalizes ip, whitelists outcome, and floors attempt_count at 1.
func encodeChallengeAttemptRow(w *gzip.Writer, ps uint32, k challengeAttemptKey, count uint64) error {
	var b strings.Builder
	b.Grow(160)
	b.WriteByte('{')
	writeString(&b, "_type", "challenge_attempt")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(k.tsMin))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "vhost", k.vhost)
	b.WriteByte(',')
	writeString(&b, "ip", k.ip)
	b.WriteByte(',')
	writeString(&b, "outcome", k.outcome)
	b.WriteByte(',')
	writeString(&b, "source", k.source)
	b.WriteByte(',')
	writeUint64(&b, "attempt_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
