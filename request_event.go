package apxstats

import (
	"compress/gzip"
	"strconv"
	"strings"
	"sync/atomic"
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

	// --- mode_v2 fields (emitted only when V2 is true) ---
	// TsUnixMs is epoch milliseconds (kept alongside TsUnixSec/`ts` for
	// back-compat). MachineID identifies the emitting Caddy machine (from
	// the app MachineID config, capped 64B). MachineSeq is a per-process
	// monotonic counter. Disposition is exactly one of the seven disp*
	// constants. Host is the lowercased, port-stripped Host header (capped
	// 255B), empty when VhostID>0 to save bytes. V2 gates both the extra
	// wire fields and the disposition-aware sampling.
	TsUnixMs    int64
	MachineID   string
	MachineSeq  uint64
	Disposition string
	Host        string
	V2          bool
}

// encodeRequestEventRow writes one NDJSON line for a raw request_event row.
// Format (field order is part of the Phoenix contract):
//
//	{"_type":"request_event","ts":"...","proxy_server_id":N,"vhost_id":N,"client_ip":"...","forwarded_ip":"...","front_proxy":"...","method":"...","path":"...","path_bucket":"...","status":N,"http_version":"...","ua":"...","origin":"...","bytes_in":N,"bytes_out":N,"duration_us":N,"sample_rate":N}
//
// When row.V2 is set, five more fields are appended after sample_rate:
// ts_ms, machine_id, machine_seq, disposition, host. This keeps the
// legacy prefix byte-identical for non-v2 rows (old configs / old ingest).
//
// ts is second-precision RFC3339 (formatTsSec). String fields go through
// writeString so arbitrary-byte values (path, ua) are JSON-escaped.
// country/asn/asn_org are intentionally absent — Phoenix enriches those
// from client_ip at ingest. status and sample_rate are uint16s emitted as
// numbers via writeUint32 (cast).
func encodeRequestEventRow(w *gzip.Writer, ps uint32, row requestEventRow) error {
	var b strings.Builder
	b.Grow(448)
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
	if row.V2 {
		// New fields appended after sample_rate so the legacy prefix stays
		// byte-identical for non-v2 rows (old configs / old ingest).
		b.WriteByte(',')
		writeInt64(&b, "ts_ms", row.TsUnixMs)
		b.WriteByte(',')
		writeString(&b, "machine_id", row.MachineID)
		b.WriteByte(',')
		writeUint64(&b, "machine_seq", row.MachineSeq)
		b.WriteByte(',')
		writeString(&b, "disposition", row.Disposition)
		b.WriteByte(',')
		writeString(&b, "host", row.Host)
	}
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// writeInt64 writes a JSON `"key":N` pair for a signed 64-bit number.
// Mirrors writeUint64 (app.go); ts_ms is int64 per the wire contract.
func writeInt64(b *strings.Builder, key string, n int64) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	b.WriteString(strconv.FormatInt(n, 10))
}

// reqEventSeqCounter is the per-process monotonic source for MachineSeq.
// Package-level (not per-app) so it stays monotonic across a Caddy
// hot-reload that swaps StatsApp instances in the same process.
var reqEventSeqCounter atomic.Uint64

// nextMachineSeq returns the next per-process request_event sequence
// number. Called once per v2 row built by the handler.
func nextMachineSeq() uint64 { return reqEventSeqCounter.Add(1) }
