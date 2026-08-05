package apxstats

import (
	"compress/gzip"
	"strings"
)

// L7HttpversionKey is the natural identity of an aggregated L7 HTTP-version
// counter row. Like L4SniKey, ProxyServerID is global per Caddy process
// (set on StatsApp at provision) so it's not part of the key, and there's
// no MachineID dimension — the Phoenix-side ingest relies on
// SummingMergeTree's cross-machine merge.
type L7HttpversionKey struct {
	TsUnixMin    uint32 // unix minute, fits 2106
	VhostID      uint32
	HttpVersion  string // "1.1" | "2" | "3" | "other"
	StatusBucket uint8  // 0..5 (leading status digit, 0 = out-of-range)
}

// l7HttpversionCounter holds the aggregated count for one L7HttpversionKey.
// Single scalar — a request arrived and was counted.
type l7HttpversionCounter struct {
	RequestCount uint64
}

// encodeL7HttpversionRow writes one NDJSON line for an L7 HTTP-version
// counter entry. Format:
//
//	{"_type":"l7_httpversion","ts":"...","proxy_server_id":N,"vhost_id":N,"http_version":"...","status_bucket":N,"request_count":N}
//
// Field order matches the Phoenix `normalize_l7_httpversion_row/1`
// contract exactly. status_bucket is emitted as a number via writeUint32
// (no writeUint8 helper exists — cast the uint8).
func encodeL7HttpversionRow(w *gzip.Writer, ps uint32, k L7HttpversionKey, c *l7HttpversionCounter) error {
	var b strings.Builder
	b.Grow(160)
	b.WriteByte('{')
	writeString(&b, "_type", "l7_httpversion")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(k.TsUnixMin))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeUint32(&b, "vhost_id", k.VhostID)
	b.WriteByte(',')
	writeString(&b, "http_version", k.HttpVersion)
	b.WriteByte(',')
	writeUint32(&b, "status_bucket", uint32(k.StatusBucket))
	b.WriteByte(',')
	writeUint64(&b, "request_count", c.RequestCount)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
