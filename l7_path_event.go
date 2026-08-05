package apxstats

import (
	"compress/gzip"
	"strings"
)

// L7PathKey is the natural identity of an aggregated L7 per-path counter
// row. Like L7HttpversionKey, ProxyServerID is global per Caddy process
// (set on StatsApp at provision) so it's not part of the key, and there's
// no MachineID dimension — Phoenix-side ingest relies on SummingMergeTree's
// cross-machine merge. TsUnixMin is stamped at DRAIN time (the recorder
// accumulates per-window without a timestamp, then the drain stamps the
// drain-minute on every row).
type L7PathKey struct {
	TsUnixMin    uint32 // unix minute, stamped at drain time
	VhostID      uint32
	PathBucket   string // already bucketed + capped to L7PathBucketMaxBytes
	StatusBucket uint8  // 0..5 (leading status digit, 0 = out-of-range)
}

// encodeL7PathRow writes one NDJSON line for an L7 per-path counter entry.
// Format:
//
//	{"_type":"l7_path","ts":"...","proxy_server_id":N,"vhost_id":N,"path_bucket":"...","status_bucket":N,"request_count":N}
//
// Field order matches the Phoenix path-row contract exactly. path_bucket is
// already bucketed + capped but goes through writeString so it's JSON-escaped
// like the other string fields. status_bucket is emitted as a number via
// writeUint32 (no writeUint8 helper exists — cast the uint8).
func encodeL7PathRow(w *gzip.Writer, ps uint32, k L7PathKey, count uint64) error {
	var b strings.Builder
	b.Grow(192)
	b.WriteByte('{')
	writeString(&b, "_type", "l7_path")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(k.TsUnixMin))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeUint32(&b, "vhost_id", k.VhostID)
	b.WriteByte(',')
	writeString(&b, "path_bucket", k.PathBucket)
	b.WriteByte(',')
	writeUint32(&b, "status_bucket", uint32(k.StatusBucket))
	b.WriteByte(',')
	writeUint64(&b, "request_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
