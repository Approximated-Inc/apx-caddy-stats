package apxstats

import (
	"compress/gzip"
	"strings"
)

// requestEventRow is one raw per-request analytics row (one per SERVED
// request). Unlike the aggregated counter rows, ts is SECOND-precision
// (per-request granularity). country/asn/asn_org are NOT on the wire —
// Phoenix fills those at ingest from the client IP, so they're absent
// here. SampleRate is the sample-under-load factor stamped by the
// recorder (1 = kept every row; n>1 = this row represents n requests).
type requestEventRow struct {
	TsUnixSec   uint32 // second precision (per-request)
	VhostID     uint32
	ClientIP    string
	ForwardedIP string
	FrontProxy  string
	Method      string
	Path        string
	PathBucket  string
	Status      uint16
	HTTPVersion string
	UA          string
	Origin      string
	BytesIn     uint64
	BytesOut    uint64
	DurationUs  uint64
	SampleRate  uint16
}

// encodeRequestEventRow writes one NDJSON line for a raw request_event row.
// Format (field order is part of the Phoenix contract):
//
//	{"_type":"request_event","ts":"...","proxy_server_id":N,"vhost_id":N,"client_ip":"...","forwarded_ip":"...","front_proxy":"...","method":"...","path":"...","path_bucket":"...","status":N,"http_version":"...","ua":"...","origin":"...","bytes_in":N,"bytes_out":N,"duration_us":N,"sample_rate":N}
//
// ts is second-precision RFC3339 (formatTsSec). String fields go through
// writeString so arbitrary-byte values (path, ua) are JSON-escaped.
// country/asn/asn_org are intentionally absent — Phoenix enriches those
// from client_ip at ingest. status and sample_rate are uint16s emitted as
// numbers via writeUint32 (cast).
func encodeRequestEventRow(w *gzip.Writer, ps uint32, row requestEventRow) error {
	var b strings.Builder
	b.Grow(384)
	b.WriteByte('{')
	writeString(&b, "_type", "request_event")
	b.WriteByte(',')
	writeString(&b, "ts", formatTsSec(row.TsUnixSec))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeUint32(&b, "vhost_id", row.VhostID)
	b.WriteByte(',')
	writeString(&b, "client_ip", row.ClientIP)
	b.WriteByte(',')
	writeString(&b, "forwarded_ip", row.ForwardedIP)
	b.WriteByte(',')
	writeString(&b, "front_proxy", row.FrontProxy)
	b.WriteByte(',')
	writeString(&b, "method", row.Method)
	b.WriteByte(',')
	writeString(&b, "path", row.Path)
	b.WriteByte(',')
	writeString(&b, "path_bucket", row.PathBucket)
	b.WriteByte(',')
	writeUint32(&b, "status", uint32(row.Status))
	b.WriteByte(',')
	writeString(&b, "http_version", row.HTTPVersion)
	b.WriteByte(',')
	writeString(&b, "ua", row.UA)
	b.WriteByte(',')
	writeString(&b, "origin", row.Origin)
	b.WriteByte(',')
	writeUint64(&b, "bytes_in", row.BytesIn)
	b.WriteByte(',')
	writeUint64(&b, "bytes_out", row.BytesOut)
	b.WriteByte(',')
	writeUint64(&b, "duration_us", row.DurationUs)
	b.WriteByte(',')
	writeUint32(&b, "sample_rate", uint32(row.SampleRate))
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
