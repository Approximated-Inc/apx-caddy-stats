package apxstats

import "testing"

func TestFingerprintHandler_CaddyModuleID(t *testing.T) {
	got := (&FingerprintHandler{}).CaddyModule().ID
	if string(got) != "layer4.handlers.apx_l4_fingerprint_stats" {
		t.Errorf("module ID = %q, want layer4.handlers.apx_l4_fingerprint_stats", got)
	}
}
