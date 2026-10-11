package apxstats

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// A CRS rule ID the image's selector catalog does not know (a newer CRS) is
// skipped and logged once at provisioning; it never rejects the config.
func TestDefenseEvidenceUnknownSelectorsAreSkipped(t *testing.T) {
	config := `{"mode":"capture","http_var":"e_http","coraza_rule_vars":{"942100":"e_rule","942999":"e_future"},"skip_coraza_rule_vars":{"942101":"e_skip","999999":"e_future_skip"}}`
	h := new(DefenseEvidenceHandler)
	require.NoError(t, json.Unmarshal([]byte(config), h))
	core, logs := observer.New(zapcore.DebugLevel)
	require.NoError(t, h.provision(zap.New(core)), "an unknown CRS selector rejected the whole config")
	require.NoError(t, h.Validate())
	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	require.Equal(t, zapcore.WarnLevel, entry.Level)
	require.Equal(t, []any{uint32(942999), uint32(999999)}, entry.ContextMap()["rule_ids"])

	stamp := evidenceHandler(t, `{"mode":"stamp_waf"}`)
	for i := 0; i < 100; i++ {
		r, _ := withDefenseSnapshotHolder(newRequestWithReplacer("GET", "/", "100", nil))
		for _, name := range []string{"e_http", "e_rule", "e_future", "e_skip", "e_future_skip"} {
			caddyhttp.SetVar(r.Context(), name, "true")
		}
		require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return stamp.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
				evidence, ok := defenseEvidenceFromHeaders(r.Header)
				require.True(t, ok, "the stamped marker did not parse")
				require.True(t, evidence.HTTP)
				require.Equal(t, []uint32{942100}, evidence.CorazaRuleIDs)
				require.Equal(t, "true", r.Header.Get("X-Apx-Coraza-Skip-942101"))
				require.Empty(t, r.Header.Values("X-Apx-Coraza-Skip-999999"))
				return nil
			}))
		})))
	}
	require.Equal(t, 1, logs.Len(), "requests logged unknown selectors again")

	// Skipping unknown IDs weakens nothing else: malformed configs still fail.
	for _, bad := range []string{
		`{"mode":"capture","coraza_rule_vars":{"0942100":"x"}}`,
		`{"mode":"capture","coraza_rule_vars":{"+942100":"x"}}`,
		`{"mode":"capture","coraza_rule_vars":{"4294967296":"x"}}`,
		`{"mode":"capture","coraza_rule_vars":{"942999":""}}`,
		`{"mode":"capture","skip_coraza_rule_vars":{"":"x"}}`,
		`{"mode":"stamp_waf","coraza_rule_vars":{"942999":"x"}}`,
	} {
		h := new(DefenseEvidenceHandler)
		require.NoError(t, json.Unmarshal([]byte(bad), h))
		require.Error(t, h.Validate(), bad)
	}
}

func TestClearDefenseMarkersAllocationFree(t *testing.T) {
	headers := benchBrowserRequest(map[string]any{}).Header
	allocs := testing.AllocsPerRun(100, func() { clearDefenseMarkers(headers) })
	require.Zero(t, allocs, "clearing markers allocated per Header name")
	headers.Set("x-APX-coraza-skip-942100", "true")
	headers["x-apx-defense-evidence"] = []string{"forged"}
	headers.Set("X-Apx-L7-Header-Exempt", "true")
	headers.Set("X-Apx-Coraza-Observe", "true")
	clearDefenseMarkers(headers)
	for name := range headers {
		require.NotContains(t, []string{"X-Apx-Coraza-Skip-942100", "x-apx-defense-evidence", "X-Apx-L7-Header-Exempt", "X-Apx-Coraza-Observe"}, name)
	}
	require.Equal(t, "100", headers.Get("X-Apx-Vhost-Id"), "an unrelated X-Apx Header was removed")
}

// Per-request capture and stamping cost must not grow with the selector
// count: the config is validated and compiled once, not on every request.
func TestDefenseEvidenceCaptureStampAllocationsIndependentOfSelectors(t *testing.T) {
	for _, n := range []int{8, 620} {
		t.Run(fmt.Sprintf("selectors=%d", n), func(t *testing.T) {
			config, vars := benchSelectorConfig(n)
			capture := evidenceHandler(t, config)
			stamp := evidenceHandler(t, `{"mode":"stamp_waf"}`)
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return stamp.ServeHTTP(w, r, benchNoop) })
			base := benchBrowserRequest(vars)
			w := httptest.NewRecorder()
			allocs := testing.AllocsPerRun(50, func() {
				r := *base
				rr, _ := withDefenseSnapshotHolder(&r)
				if err := capture.ServeHTTP(w, rr, next); err != nil {
					t.Fatal(err)
				}
			})
			require.LessOrEqual(t, allocs, 16.0, "capture and stamp allocate per selector")
		})
	}
}
