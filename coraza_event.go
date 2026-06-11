package apxstats

import (
	"compress/gzip"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

// CorazaMaxEventsDefault caps the per-flush-window detection slice when
// the operator hasn't set CorazaMaxEvents explicitly. A non-zero default
// (unlike the fingerprint caps, which default to "disabled") because the
// writer only records at all when the WAF config selects it via
// `SecAuditLogType apx_stats`; the per-cluster kill switch lives upstream
// (Phoenix flag + config-gen), not in this cap. Sized generously so a
// detect-only ruleset under attack still ships most events; overflow
// drops+counts.
const CorazaMaxEventsDefault = 200_000

// corazaMatchDataMaxBytes caps the attacker-controlled match_data field
// before it leaves the process. Phoenix re-caps at 512 too, but capping
// here keeps the wire payload bounded. Byte-safe (UTF-8 boundary aware).
const corazaMatchDataMaxBytes = 512

// Row-width caps applied BEFORE buffering (Phoenix re-caps on ingest,
// but the Go buffer holds raw values until flush — the memory hazard).
// Truncating up front means the governor's byte budget buys more rows
// and a long-URI flood can't bloat each one. Same truncateBytes
// discipline as corazaMatchDataMaxBytes.
const (
	corazaRuleMsgMaxBytes     = 256
	corazaRequestURIMaxBytes  = 2048
	corazaRequestHostMaxBytes = 255
)

// corazaDetectionFixedBytes over-approximates the in-memory fixed cost of
// one buffered detection: unsafe.Sizeof(corazaDetection{}) (~176 on
// 64-bit) plus a little append slack. Pinned by a test against the real
// Sizeof so struct growth can't silently undercount the byte budget.
const corazaDetectionFixedBytes = 184

// corazaDetectionBytes approximates the resident bytes one buffered
// detection holds: the fixed struct size, every string field's backing
// bytes, and per-tag string headers + bytes.
func corazaDetectionBytes(ev *corazaDetection) int {
	n := corazaDetectionFixedBytes +
		len(ev.Severity) + len(ev.RuleMsg) + len(ev.TxID) +
		len(ev.RequestURI) + len(ev.RequestMethod) + len(ev.RequestHost) +
		len(ev.ClientIP) + len(ev.MatchData)
	for _, tag := range ev.Tags {
		n += len(tag) + 16 // string header in the backing array + bytes
	}
	return n
}

// corazaDetection is one raw per-(request, rule) WAF detection event.
// NOT aggregated — each fired rule on each request is its own event,
// carrying its own tx_id / ts / match_data. Stored append-only in a
// capped slice on StatsApp and emitted as one `_type:"coraza_detection"`
// NDJSON row per event.
type corazaDetection struct {
	TsUnixSec     uint32 // detection time (audit unix_timestamp ns -> sec)
	VhostID       uint32 // from X-Apx-Vhost-Id request header; 0 if absent
	RuleID        uint32 // fired rule id, e.g. 942100
	Severity      string // UPPERCASE label (EMERGENCY..DEBUG)
	RuleMsg       string
	Tags          []string
	TxID          string
	RequestURI    string
	RequestMethod string
	RequestHost   string
	ClientIP      string // audit-log Transaction().ClientIP() — real PROXY-derived client IP (NOT XFF)
	MatchData     string // truncated to corazaMatchDataMaxBytes
	WasBlocked    bool
}

// formatTsSec renders a Unix-second as RFC3339 UTC. Detection events
// carry second granularity (unlike the minute-aligned counter rows), so
// they get their own formatter; the output is still an RFC3339 string
// that the Phoenix `parse_ts` (DateTime.from_iso8601/1) accepts.
func formatTsSec(unixSec uint32) string {
	return time.Unix(int64(unixSec), 0).UTC().Format(time.RFC3339)
}

// corazaSeverityLabel maps Coraza's numeric RuleSeverity (0=Emergency …
// 7=Debug) to the UPPERCASE RFC-5424 label the Phoenix consumer expects.
// Unset / out-of-range maps to "UNKNOWN" (Phoenix re-validates anyway).
func corazaSeverityLabel(s types.RuleSeverity) string {
	switch s {
	case types.RuleSeverityEmergency:
		return "EMERGENCY"
	case types.RuleSeverityAlert:
		return "ALERT"
	case types.RuleSeverityCritical:
		return "CRITICAL"
	case types.RuleSeverityError:
		return "ERROR"
	case types.RuleSeverityWarning:
		return "WARNING"
	case types.RuleSeverityNotice:
		return "NOTICE"
	case types.RuleSeverityInfo:
		return "INFO"
	case types.RuleSeverityDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

// truncateBytes caps s to at most max bytes without splitting a UTF-8
// code point (walks back over trailing continuation bytes). Mirrors the
// Phoenix-side truncate_bytes/2 so both ends agree on the boundary.
func truncateBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	end := max
	// Back up over UTF-8 continuation bytes (0b10xxxxxx) so we don't cut
	// a multi-byte sequence in half.
	for end > 0 && s[end]&0xC0 == 0x80 {
		end--
	}
	// Clone into a right-sized allocation: s[:end] would share (pin) the
	// parent's full backing array while the byte accounting counts only
	// the truncated length.
	return strings.Clone(s[:end])
}

// encodeCorazaDetectionRow emits one `_type: "coraza_detection"` NDJSON
// row. proxyServerID is the config-injected cluster id (global), not from
// the audit record. Mirrors the hand-rolled writer style of the
// fingerprint encoders.
//
//	{"_type":"coraza_detection","ts":"...","proxy_server_id":N,"vhost_id":N,
//	 "rule_id":N,"severity":"...","rule_msg":"...","tags":[...],"tx_id":"...",
//	 "request_uri":"...","request_method":"...","request_host":"...",
//	 "client_ip":"...","match_data":"...","was_blocked":N}
func encodeCorazaDetectionRow(w *gzip.Writer, ev corazaDetection, proxyServerID uint32) error {
	var b strings.Builder
	b.Grow(448)
	b.WriteByte('{')
	writeString(&b, "_type", "coraza_detection")
	b.WriteByte(',')
	writeString(&b, "ts", formatTsSec(ev.TsUnixSec))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", proxyServerID)
	b.WriteByte(',')
	writeUint32(&b, "vhost_id", ev.VhostID)
	b.WriteByte(',')
	writeUint32(&b, "rule_id", ev.RuleID)
	b.WriteByte(',')
	writeString(&b, "severity", ev.Severity)
	b.WriteByte(',')
	writeString(&b, "rule_msg", ev.RuleMsg)
	b.WriteByte(',')
	writeStringArray(&b, "tags", ev.Tags)
	b.WriteByte(',')
	writeString(&b, "tx_id", ev.TxID)
	b.WriteByte(',')
	writeString(&b, "request_uri", ev.RequestURI)
	b.WriteByte(',')
	writeString(&b, "request_method", ev.RequestMethod)
	b.WriteByte(',')
	writeString(&b, "request_host", ev.RequestHost)
	b.WriteByte(',')
	writeString(&b, "client_ip", ev.ClientIP)
	b.WriteByte(',')
	writeString(&b, "match_data", ev.MatchData)
	b.WriteByte(',')
	writeUint32(&b, "was_blocked", boolToUint32(ev.WasBlocked))
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// writeStringArray writes a JSON `"key":[...]` pair of JSON-escaped
// strings. Reuses the writeString escaping discipline per element.
func writeStringArray(b *strings.Builder, key string, vals []string) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":[`)
	for i, v := range vals {
		if i > 0 {
			b.WriteByte(',')
		}
		if needsJSONEscape(v) {
			b.WriteString(jsonEscape(v))
		} else {
			b.WriteByte('"')
			b.WriteString(v)
			b.WriteByte('"')
		}
	}
	b.WriteByte(']')
}
