package apxstats

import (
	"compress/gzip"
	"strings"
)

// edgeVerifyAttemptKey is the natural identity of an aggregated
// edge_verify_attempt counter row. Like challengeAttemptKey,
// ProxyServerID is global per Caddy process (stamped at encode time) so
// it's not part of the key. No TsUnixMin field — the minute is stamped at
// drain/encode time (the flush minute), mirroring the challenge-attempt
// track. Edge Verify has no per-client dimension recorded at the edge
// (apx_verify_outcome is per-request, not per-IP), so the second dimension
// is `path_bucket` (the low-cardinality bucketed request path) rather than
// the challenge track's `ip`. vhost is the lowercased Host header — the
// Edge Verify handler runs before the per-vhost vars handler resolves
// vhost_id, so we key on Host, NOT vhost_id.
type edgeVerifyAttemptKey struct {
	vhost      string // lowercased Host header, port stripped
	pathBucket string // low-cardinality bucketed request path (pathBucket())
	outcome    string // passed | missing | invalid | expired | replayed
}

// edgeVerifyMaxKeys caps distinct (vhost, path_bucket, outcome) keys per
// flush window. A count cap (not the byte governor) is enough here: rows
// are tiny and bounded-width (vhost is capped by challengeVhost), so 50K
// keys is a few MB worst case. New keys past the cap are dropped + counted
// (edgeVerifyOverflow + metric), mirroring the challengeMaxKeys
// overflow-telemetry pattern; existing keys keep counting.
const edgeVerifyMaxKeys = 50_000

// encodeEdgeVerifyAttemptRow writes one NDJSON line for an aggregated
// edge_verify_attempt counter entry. Format (field order is part of
// the Phoenix contract — `_type` MUST be first):
//
//	{"_type":"edge_verify_attempt","ts":"...","proxy_server_id":N,"vhost":"...","path_bucket":"...","outcome":"...","attempt_count":N}
//
// ts is minute-precision RFC3339 (formatTs), stamped with the flush
// minute. Matches the `normalize_edge_verify_attempt_row/1` clause in
// the Phoenix analytics ingest controller, which downcases vhost, bounds
// path_bucket, whitelists outcome, and floors attempt_count at 1.
func encodeEdgeVerifyAttemptRow(w *gzip.Writer, ps, ts uint32, k edgeVerifyAttemptKey, count uint64) error {
	var b strings.Builder
	b.Grow(176)
	b.WriteByte('{')
	writeString(&b, "_type", "edge_verify_attempt")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(ts))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "vhost", k.vhost)
	b.WriteByte(',')
	writeString(&b, "path_bucket", k.pathBucket)
	b.WriteByte(',')
	writeString(&b, "outcome", k.outcome)
	b.WriteByte(',')
	writeUint64(&b, "attempt_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
