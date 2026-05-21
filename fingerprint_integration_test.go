package apxstats

import (
	"strings"
	"testing"
	"time"
)

// TestFingerprint_endToEnd proves the full data path:
// cx vars set by l4tls.MatchTLS → FingerprintHandler.Handle records →
// fingerprintSnapshot/fingerprintIpSnapshot drain →
// encodeBatch emits NDJSON whose shape matches the Phase 3a ingest contract.
func TestFingerprint_endToEnd(t *testing.T) {
	a := newTestAppWithFP(5000, 10000)
	h := &FingerprintHandler{app: a}
	ja3 := "0123456789abcdef0123456789abcdef"
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"

	// Two connections, same fingerprint, same IP → traffic count 2, ip count 2.
	for i := 0; i < 2; i++ {
		cx := newTestConn(t, "1.2.3.4:5555", map[string]any{"tls_ja3": ja3, "tls_ja4": ja4})
		if err := h.Handle(cx, &fakeNext{}); err != nil {
			t.Fatal(err)
		}
	}

	fpSnap := a.fingerprintSnapshot()
	fpIpSnap := a.fingerprintIpSnapshot()
	body, err := encodeBatch(a.ProxyServerIDValue, uint32(time.Now().Unix()/60),
		nil, nil, nil, l4IpSnap{}, fpSnap, fpIpSnap)
	if err != nil {
		t.Fatal(err)
	}

	out := gunzipString(t, body)

	// Split into non-empty lines for precise per-row assertions.
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("expected exactly 2 NDJSON lines, got %d:\n%s", len(lines), out)
	}

	// Find each row by type.
	var fpRow, fpIpRow string
	for _, line := range lines {
		switch {
		case strings.Contains(line, `"_type":"l4_fingerprint"`):
			fpRow = line
		case strings.Contains(line, `"_type":"l4_fingerprint_ip"`):
			fpIpRow = line
		}
	}

	if fpRow == "" {
		t.Errorf("missing l4_fingerprint row:\n%s", out)
	} else {
		if !strings.Contains(fpRow, `"ja3":"`+ja3+`"`) {
			t.Errorf("l4_fingerprint row missing ja3:\n%s", fpRow)
		}
		if !strings.Contains(fpRow, `"ja4":"`+ja4+`"`) {
			t.Errorf("l4_fingerprint row missing ja4:\n%s", fpRow)
		}
		if !strings.Contains(fpRow, `"connection_count":2`) {
			t.Errorf("l4_fingerprint row has wrong connection_count:\n%s", fpRow)
		}
		if !strings.Contains(fpRow, `"outcome":"allowed"`) {
			t.Errorf("l4_fingerprint row missing outcome:\n%s", fpRow)
		}
	}

	if fpIpRow == "" {
		t.Errorf("missing l4_fingerprint_ip row:\n%s", out)
	} else {
		if !strings.Contains(fpIpRow, `"ip":"1.2.3.4"`) {
			t.Errorf("l4_fingerprint_ip row missing ip:\n%s", fpIpRow)
		}
		if !strings.Contains(fpIpRow, `"ja4":"`+ja4+`"`) {
			t.Errorf("l4_fingerprint_ip row missing ja4:\n%s", fpIpRow)
		}
		if !strings.Contains(fpIpRow, `"connection_count":2`) {
			t.Errorf("l4_fingerprint_ip row has wrong connection_count:\n%s", fpIpRow)
		}
	}
}
