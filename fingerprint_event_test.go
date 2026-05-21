package apxstats

import "testing"

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
