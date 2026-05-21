package apxstats

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

func gunzipString(t *testing.T, b []byte) string {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestEncodeL4FingerprintRow(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if err := encodeL4FingerprintRow(gz, 89, 30000000, "0123456789abcdef0123456789abcdef", ja4, "allowed", 7); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	got := gunzipString(t, buf.Bytes())
	want := `{"_type":"l4_fingerprint","ts":"` + formatTs(30000000) +
		`","proxy_server_id":89,"ja3":"0123456789abcdef0123456789abcdef","ja4":"` + ja4 +
		`","outcome":"allowed","connection_count":7}` + "\n"
	if got != want {
		t.Errorf("row =\n  %q\nwant\n  %q", got, want)
	}
}

func TestEncodeL4FingerprintIpRow(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if err := encodeL4FingerprintIpRow(gz, 89, 30000000, ja4, "1.2.3.4", 5); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	got := gunzipString(t, buf.Bytes())
	want := `{"_type":"l4_fingerprint_ip","ts":"` + formatTs(30000000) +
		`","proxy_server_id":89,"ja4":"` + ja4 +
		`","ip":"1.2.3.4","connection_count":5}` + "\n"
	if got != want {
		t.Errorf("row =\n  %q\nwant\n  %q", got, want)
	}
}

func newTestAppWithFP(maxKeys, maxIpKeys int) *StatsApp {
	a := &StatsApp{ProxyServerIDValue: 89}
	a.cfg.fingerprintMaxKeys = maxKeys
	a.cfg.fingerprintIpMaxKeys = maxIpKeys
	a.fpMap = make(map[fingerprintKey]*fingerprintCounter)
	a.fpIpMap = make(map[fingerprintIpKey]*fingerprintCounter)
	return a
}

func TestRecordFingerprint_capDropsNewKeys(t *testing.T) {
	a := newTestAppWithFP(2, 100) // tiny traffic cap
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	a.RecordFingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ja4, "1.2.3.4")
	a.RecordFingerprint("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ja4, "1.2.3.4")
	a.RecordFingerprint("cccccccccccccccccccccccccccccccc", ja4, "1.2.3.4") // 3rd distinct -> dropped

	a.fpMu.Lock()
	n := len(a.fpMap)
	a.fpMu.Unlock()
	if n != 2 {
		t.Errorf("fpMap size = %d, want 2 (cap enforced)", n)
	}
	// Re-recording an existing key still increments (not dropped).
	a.RecordFingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ja4, "1.2.3.4")
	a.fpMu.Lock()
	c := a.fpMap[fingerprintKey{TsUnixMin: timeNowUnixMin(), JA3: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", JA4: ja4, Outcome: FingerprintOutcomeAllowed}]
	a.fpMu.Unlock()
	if c == nil || c.ConnectionCount != 2 {
		t.Errorf("existing key not incremented past cap; got %+v", c)
	}
}

func TestRecordFingerprint_overflowCounter(t *testing.T) {
	a := newTestAppWithFP(1, 0) // ip map disabled
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	a.RecordFingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ja4, "")
	a.RecordFingerprint("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ja4, "") // dropped
	if a.fpOverflow != 1 {
		t.Errorf("fpOverflow = %d, want 1", a.fpOverflow)
	}
}

// With the ip map enabled, an empty IP must still record the traffic row
// but skip the (ja4, ip) join row (the ip != "" guard).
func TestRecordFingerprint_emptyIPSkipsIPMap(t *testing.T) {
	a := newTestAppWithFP(5000, 10000)
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	a.RecordFingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ja4, "")

	a.fpMu.Lock()
	nfp, nip := len(a.fpMap), len(a.fpIpMap)
	a.fpMu.Unlock()
	if nfp != 1 {
		t.Errorf("fpMap size = %d, want 1 (traffic row recorded)", nfp)
	}
	if nip != 0 {
		t.Errorf("fpIpMap size = %d, want 0 (empty IP must skip the join row)", nip)
	}
}

func TestFingerprintSnapshot_shipsAllCountGE1(t *testing.T) {
	a := newTestAppWithFP(5000, 10000)
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	ja3a := "0123456789abcdef0123456789abcdef"
	ja3b := "fedcba9876543210fedcba9876543210"
	// One key seen twice (count 2) and a distinct key seen once (count 1):
	// the count-1 key must NOT be dropped (unlike drainL4SniRows).
	a.RecordFingerprint(ja3a, ja4, "1.2.3.4")
	a.RecordFingerprint(ja3a, ja4, "1.2.3.4")
	a.RecordFingerprint(ja3b, ja4, "1.2.3.4")
	snap := a.fingerprintSnapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot size = %d, want 2 (count==1 key must NOT be dropped)", len(snap))
	}
	min := timeNowUnixMin()
	if c := snap[fingerprintKey{TsUnixMin: min, JA3: ja3a, JA4: ja4, Outcome: FingerprintOutcomeAllowed}]; c == nil || c.ConnectionCount != 2 {
		t.Errorf("count-2 key = %+v, want ConnectionCount 2", c)
	}
	if c := snap[fingerprintKey{TsUnixMin: min, JA3: ja3b, JA4: ja4, Outcome: FingerprintOutcomeAllowed}]; c == nil || c.ConnectionCount != 1 {
		t.Errorf("count-1 key = %+v, want ConnectionCount 1 (must ship)", c)
	}
	// map reset after snapshot
	a.fpMu.Lock()
	n := len(a.fpMap)
	a.fpMu.Unlock()
	if n != 0 {
		t.Errorf("fpMap not reset after snapshot: %d", n)
	}
}

func TestFingerprintIpSnapshot_resetsAndKeepsCount1(t *testing.T) {
	a := newTestAppWithFP(5000, 10000)
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	a.RecordFingerprint("0123456789abcdef0123456789abcdef", ja4, "1.2.3.4") // records one (ja4, ip) pair
	snap := a.fingerprintIpSnapshot()
	if len(snap) != 1 {
		t.Fatalf("fingerprintIpSnapshot size = %d, want 1 (count==1 must NOT be dropped)", len(snap))
	}
	// verify the single entry has count 1
	for _, c := range snap {
		if c.ConnectionCount != 1 {
			t.Errorf("ConnectionCount = %d, want 1", c.ConnectionCount)
		}
	}
	// map reset after snapshot
	a.fpMu.Lock()
	n := len(a.fpIpMap)
	a.fpMu.Unlock()
	if n != 0 {
		t.Errorf("fpIpMap not reset after snapshot: %d", n)
	}
}
