package apxstats

import (
	"compress/gzip"
	"strings"
)

// challengeAttemptKey is the natural identity of an aggregated
// challenge_attempt counter row. Like L4SniKey, ProxyServerID is global
// per Caddy process (stamped at encode time) so it's not part of the
// key. No TsUnixMin field — the minute is stamped at drain/encode time
// (the flush minute), mirroring the L4 IP / fingerprint tracks rather
// than the record-time minute of the L4 SNI track. A served challenge is
// terminal (the apx_challenge handler returns without calling next), so
// the per-vhost vars handler never runs and vhost_id is unset — the
// dimension is therefore the lowercased Host header, NOT vhost_id.
type challengeAttemptKey struct {
	vhost   string // lowercased Host header, port stripped
	ip      string // security client IP (PROXY-decoded RemoteAddr)
	outcome string // issued | passed | passed_recently | failed
}

// encodeChallengeAttemptRow writes one NDJSON line for an aggregated
// challenge_attempt counter entry. Format (field order is part of the
// Phoenix contract — `_type` MUST be first):
//
//	{"_type":"challenge_attempt","ts":"...","proxy_server_id":N,"vhost":"...","ip":"...","outcome":"...","attempt_count":N}
//
// ts is minute-precision RFC3339 (formatTs), stamped with the flush
// minute. Matches the `normalize_challenge_attempt_row/1` clause in the
// Phoenix analytics ingest controller, which downcases vhost,
// canonicalizes ip, whitelists outcome, and floors attempt_count at 1.
func encodeChallengeAttemptRow(w *gzip.Writer, ps, ts uint32, k challengeAttemptKey, count uint64) error {
	var b strings.Builder
	b.Grow(160)
	b.WriteByte('{')
	writeString(&b, "_type", "challenge_attempt")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(ts))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "vhost", k.vhost)
	b.WriteByte(',')
	writeString(&b, "ip", k.ip)
	b.WriteByte(',')
	writeString(&b, "outcome", k.outcome)
	b.WriteByte(',')
	writeUint64(&b, "attempt_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
