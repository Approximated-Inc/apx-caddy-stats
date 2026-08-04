package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"

	"github.com/corazawaf/coraza/v3/types"
)

func TestEncodeCorazaDetectionRow(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	ev := corazaDetection{
		TsUnixSec:     30_000_000,
		VhostID:       7,
		RuleID:        942100,
		Severity:      "CRITICAL",
		RuleMsg:       "SQL Injection Attack Detected",
		Tags:          []string{"application-multi", "attack-sqli"},
		TxID:          "abc123",
		RequestURI:    "/login?id=1",
		RequestMethod: "POST",
		RequestHost:   "example.com",
		ClientIP:      "203.0.113.7",
		MatchData:     "Matched Data: ' OR 1=1",
		WasBlocked:    true,
	}
	if err := encodeCorazaDetectionRow(gz, ev, 89); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	got := gunzipString(t, buf.Bytes())
	want := `{"_type":"coraza_detection","ts":"` + formatTsSec(30_000_000) +
		`","proxy_server_id":89,"vhost_id":7,"rule_id":942100,"severity":"CRITICAL",` +
		`"rule_msg":"SQL Injection Attack Detected","tags":["application-multi","attack-sqli"],` +
		`"tx_id":"abc123","request_uri":"/login?id=1","request_method":"POST",` +
		`"request_host":"example.com","client_ip":"203.0.113.7",` +
		`"match_data":"Matched Data: ' OR 1=1","was_blocked":1}` + "\n"
	if got != want {
		t.Errorf("row =\n  %q\nwant\n  %q", got, want)
	}
	if !strings.Contains(got, `"client_ip":"203.0.113.7"`) {
		t.Errorf("expected client_ip in row, got %q", got)
	}
}

func TestEncodeCorazaDetectionRow_emptyTagsAndNotBlocked(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	ev := corazaDetection{
		TsUnixSec:  30_000_000,
		VhostID:    0,
		RuleID:     0,
		Severity:   "UNKNOWN",
		Tags:       nil,
		WasBlocked: false,
	}
	if err := encodeCorazaDetectionRow(gz, ev, 1); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	got := gunzipString(t, buf.Bytes())
	if !strings.Contains(got, `"tags":[]`) {
		t.Errorf("expected empty tags array, got %q", got)
	}
	if !strings.Contains(got, `"was_blocked":0`) {
		t.Errorf("expected was_blocked 0, got %q", got)
	}
	if !strings.Contains(got, `"vhost_id":0`) {
		t.Errorf("expected vhost_id 0, got %q", got)
	}
	if !strings.Contains(got, `"client_ip":""`) {
		t.Errorf("expected empty client_ip, got %q", got)
	}
}

func TestEncodeCorazaDetectionRow_escapesStrings(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	ev := corazaDetection{
		RuleMsg:   `quote " and backslash \`,
		MatchData: "ctrl\x01char",
		Tags:      []string{`tag"with"quotes`},
	}
	if err := encodeCorazaDetectionRow(gz, ev, 1); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	got := gunzipString(t, buf.Bytes())
	if !strings.Contains(got, `\"`) || !strings.Contains(got, `\\`) {
		t.Errorf("expected escaped quote/backslash in row, got %q", got)
	}
	// Validate the row is parseable JSON (escaping is well-formed).
	line := strings.TrimRight(got, "\n")
	if !json.Valid([]byte(line)) {
		t.Errorf("row is not valid JSON: %q", line)
	}
}

func TestCorazaSeverityLabel(t *testing.T) {
	cases := map[types.RuleSeverity]string{
		types.RuleSeverityEmergency: "EMERGENCY",
		types.RuleSeverityAlert:     "ALERT",
		types.RuleSeverityCritical:  "CRITICAL",
		types.RuleSeverityError:     "ERROR",
		types.RuleSeverityWarning:   "WARNING",
		types.RuleSeverityNotice:    "NOTICE",
		types.RuleSeverityInfo:      "INFO",
		types.RuleSeverityDebug:     "DEBUG",
		types.RuleSeverityUnset:     "UNKNOWN",
	}
	for sev, want := range cases {
		if got := corazaSeverityLabel(sev); got != want {
			t.Errorf("corazaSeverityLabel(%d) = %q, want %q", int(sev), got, want)
		}
	}
	// Spot-check the numeric value the task calls out explicitly: 2 -> CRITICAL.
	if got := corazaSeverityLabel(types.RuleSeverity(2)); got != "CRITICAL" {
		t.Errorf("severity 2 = %q, want CRITICAL", got)
	}
}

func TestTruncateBytes(t *testing.T) {
	// Short string passes through.
	if got := truncateBytes("hello", 512); got != "hello" {
		t.Errorf("short string truncated: %q", got)
	}
	// Exactly at cap passes through.
	at := strings.Repeat("a", 512)
	if got := truncateBytes(at, 512); got != at {
		t.Errorf("at-cap string altered: len=%d", len(got))
	}
	// Over cap truncates to <= 512 bytes.
	over := strings.Repeat("a", 600)
	got := truncateBytes(over, 512)
	if len(got) != 512 {
		t.Errorf("len = %d, want 512", len(got))
	}
}

func TestTruncateBytes_cloneReleasesParentBacking(t *testing.T) {
	// Truncation must copy into a right-sized allocation: returning
	// s[:end] would share (pin) the parent's full backing array while the
	// governor's byte accounting counts only the truncated length.
	parent := strings.Repeat("a", 1<<20)
	got := truncateBytes(parent, 512)
	if len(got) != 512 {
		t.Fatalf("len = %d, want 512", len(got))
	}
	if unsafe.StringData(got) == unsafe.StringData(parent) {
		t.Errorf("truncated result shares the parent's backing array; want a clone")
	}
	// The common short-string path must stay copy-free: same backing.
	short := "hello"
	if got := truncateBytes(short, 512); unsafe.StringData(got) != unsafe.StringData(short) {
		t.Errorf("short string was needlessly copied")
	}
}

func TestOwnedTruncate_neverSharesBacking(t *testing.T) {
	parent := strings.Repeat("a", 1<<20)

	// Under-cap input: content preserved, backing NOT shared (this is the
	// difference from truncateBytes, whose under-cap path is copy-free).
	short := parent[:10]
	got := ownedTruncate(short, 512)
	if got != short {
		t.Errorf("got %q, want %q", got, short)
	}
	if unsafe.StringData(got) == unsafe.StringData(parent) {
		t.Errorf("under-cap result shares the parent's backing array; want an owned copy")
	}

	// Over-cap input: truncated to the cap, backing not shared.
	got2 := ownedTruncate(parent, 512)
	if len(got2) != 512 {
		t.Errorf("len = %d, want 512", len(got2))
	}
	if unsafe.StringData(got2) == unsafe.StringData(parent) {
		t.Errorf("truncated result shares the parent's backing array; want an owned copy")
	}

	// UTF-8 boundary safety matches truncateBytes (511 ASCII + 2-byte é,
	// cut at 512 drops the partial é).
	s := strings.Repeat("a", 511) + "é"
	got3 := ownedTruncate(s, 512)
	if len(got3) != 511 || !utf8.ValidString(got3) {
		t.Errorf("utf8 boundary: len=%d valid=%v", len(got3), utf8.ValidString(got3))
	}
}

func TestTruncateBytes_utf8Boundary(t *testing.T) {
	// "é" is 2 bytes (0xC3 0xA9). Build 511 ASCII + one é so the cut at
	// 512 lands mid-codepoint; truncate must drop the partial é, yielding
	// 511 bytes of valid UTF-8.
	s := strings.Repeat("a", 511) + "é"
	got := truncateBytes(s, 512)
	if len(got) != 511 {
		t.Errorf("len = %d, want 511 (partial é dropped)", len(got))
	}
	if !utf8.ValidString(got) {
		t.Errorf("result is not valid UTF-8: %q", got)
	}
}
