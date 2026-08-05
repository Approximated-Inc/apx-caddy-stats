package apxstats

import (
	"compress/gzip"
	"strings"
)

const (
	// FingerprintMaxKeysDefault caps distinct (ja3, ja4, outcome) keys per
	// machine per minute (spec #17). FingerprintIpMaxKeysDefault caps
	// distinct (ja4, ip) keys. 0 in IngestConfig disables the track.
	FingerprintMaxKeysDefault   = 5000
	FingerprintIpMaxKeysDefault = 10000

	// FingerprintOutcomeAllowed is the only outcome this handler emits in
	// v1 (D1) — connections reaching this recorder were allowed; block
	// routes close blocked connections upstream. Mirrors L4IpOutcomeAllowed.
	FingerprintOutcomeAllowed = "allowed"
)

// fingerprintKey is the natural identity of an aggregated fingerprint
// traffic row. TsUnixMin is set at record time (like L4SniKey) so a key
// straddling a minute boundary lands in the right bucket.
type fingerprintKey struct {
	TsUnixMin uint32
	JA3       string
	JA4       string
	Outcome   string
}

// fingerprintIpKey is the natural identity of an aggregated
// (ja4, ip) join row.
type fingerprintIpKey struct {
	TsUnixMin uint32
	JA4       string
	IP        string
}

type fingerprintCounter struct{ ConnectionCount uint64 }

// encodeL4FingerprintRow emits one `_type: "l4_fingerprint"` NDJSON row.
//
//	{"_type":"l4_fingerprint","ts":"...","proxy_server_id":N,"ja3":"...","ja4":"...","outcome":"...","connection_count":N}
func encodeL4FingerprintRow(w *gzip.Writer, ps, ts uint32, ja3, ja4, outcome string, count uint64) error {
	var b strings.Builder
	b.Grow(224)
	b.WriteByte('{')
	writeString(&b, "_type", "l4_fingerprint")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(ts))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "ja3", ja3)
	b.WriteByte(',')
	writeString(&b, "ja4", ja4)
	b.WriteByte(',')
	writeString(&b, "outcome", outcome)
	b.WriteByte(',')
	writeUint64(&b, "connection_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// encodeL4FingerprintIpRow emits one `_type: "l4_fingerprint_ip"` NDJSON row.
//
//	{"_type":"l4_fingerprint_ip","ts":"...","proxy_server_id":N,"ja4":"...","ip":"...","connection_count":N}
func encodeL4FingerprintIpRow(w *gzip.Writer, ps, ts uint32, ja4, ip string, count uint64) error {
	var b strings.Builder
	b.Grow(192)
	b.WriteByte('{')
	writeString(&b, "_type", "l4_fingerprint_ip")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(ts))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "ja4", ja4)
	b.WriteByte(',')
	writeString(&b, "ip", ip)
	b.WriteByte(',')
	writeUint64(&b, "connection_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
