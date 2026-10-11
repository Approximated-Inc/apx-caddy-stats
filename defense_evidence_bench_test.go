package apxstats

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// benchEvidenceHandler loads a handler the way Caddy does: JSON, Provision
// (when the module has one), then Validate.
func benchEvidenceHandler(b *testing.B, config string) *DefenseEvidenceHandler {
	b.Helper()
	h := new(DefenseEvidenceHandler)
	if err := json.Unmarshal([]byte(config), h); err != nil {
		b.Fatal(err)
	}
	if p, ok := any(h).(caddy.Provisioner); ok {
		if err := p.Provision(caddy.Context{Context: context.Background()}); err != nil {
			b.Fatal(err)
		}
	}
	if err := h.Validate(); err != nil {
		b.Fatal(err)
	}
	return h
}

// benchBrowserRequest is an ordinary browser GET carrying the vars the
// generated classification routes set: every selector variable "false"
// except two.
func benchBrowserRequest(vars map[string]any) *http.Request {
	r := httptest.NewRequest("GET", "http://shop.example.com/products/blue-shirt?color=blue", nil)
	for _, h := range [][2]string{
		{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Cookie", "session=abc"},
		{"Referer", "https://shop.example.com/"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Dest", "document"},
		{"Upgrade-Insecure-Requests", "1"},
		{"X-Forwarded-For", "198.51.100.7"},
		{"Cache-Control", "no-cache"},
		{"X-Apx-Vhost-Id", "100"},
	} {
		r.Header.Set(h[0], h[1])
	}
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, vars)
	return r.WithContext(ctx)
}

func benchSelectorConfig(n int) (string, map[string]any) {
	rule, skip := map[string]string{}, map[string]string{}
	vars := map[string]any{"vhost_id": "100", "apx_defense_exclude_http_request_evidence": "false",
		"apx_defense_exclude_all_coraza_finding_evidence": "false", "apx_defense_observe_coraza": "false"}
	for i := 0; i < n && i < len(defenseCRSIDs); i++ {
		id := defenseCRSIDs[i]
		ruleVar := fmt.Sprintf("apx_defense_exclude_coraza_%d", id)
		skipVar := fmt.Sprintf("apx_defense_skip_coraza_%d", id)
		rule[fmt.Sprint(id)], skip[fmt.Sprint(id)] = ruleVar, skipVar
		vars[ruleVar], vars[skipVar] = "false", "false"
		if i == n/2 || i == n-1 {
			vars[ruleVar], vars[skipVar] = "true", "true"
		}
	}
	config, _ := json.Marshal(map[string]any{"mode": "capture", "http_var": "apx_defense_exclude_http_request_evidence",
		"coraza_all_var": "apx_defense_exclude_all_coraza_finding_evidence", "observe_coraza_var": "apx_defense_observe_coraza",
		"coraza_rule_vars": rule, "skip_coraza_rule_vars": skip})
	return string(config), vars
}

var benchNoop = caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })

// One request through the capture and stamp_waf handlers, including the
// per-request holder the outer apx_stats handler attaches.
func BenchmarkDefenseEvidenceCaptureStamp(b *testing.B) {
	for _, n := range []int{8, 200, 620} {
		b.Run(fmt.Sprintf("selectors=%d", n), func(b *testing.B) {
			config, vars := benchSelectorConfig(n)
			capture := benchEvidenceHandler(b, config)
			stamp := benchEvidenceHandler(b, `{"mode":"stamp_waf"}`)
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return stamp.ServeHTTP(w, r, benchNoop) })
			base := benchBrowserRequest(vars)
			w := httptest.NewRecorder()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := *base
				r.Header = base.Header.Clone()
				rr, _ := withDefenseSnapshotHolder(&r)
				if err := capture.ServeHTTP(w, rr, next); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// One request through capture_privacy plus the WAF connector's Bind, two
// Redact calls (rule_msg, match_data) and release.
func BenchmarkManagedHeaderPrivacyRequest(b *testing.B) {
	for _, n := range []int{8, 128} {
		for _, carries := range []bool{false, true} {
			b.Run(fmt.Sprintf("names=%d/carries=%v", n, carries), func(b *testing.B) {
				pairs := make([]managedHeaderCredential, n)
				for i := range pairs {
					pairs[i] = managedHeaderCredential{Name: fmt.Sprintf("X-Partner-Key-%03d", i), Value: fmt.Sprintf("partner-secret-%03d-0123456789abcdef", i)}
				}
				config, _ := json.Marshal(map[string]any{"mode": "capture_privacy", "managed_headers": pairs})
				privacy := benchEvidenceHandler(b, string(config))
				bridge := &CorazaPrivacyBridge{}
				ids := make([]string, 1024)
				for i := range ids {
					ids[i] = fmt.Sprintf("%064x", i)
				}
				var sink string
				i := 0
				next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					id := ids[i&1023]
					release := bridge.Bind(id, r)
					sink = bridge.Redact(id, "Inbound Anomaly Score Exceeded (Total Score: 5)")
					sink = bridge.Redact(id, "Matched Data: <script> found within ARGS:q")
					release()
					return nil
				})
				base := benchBrowserRequest(map[string]any{"vhost_id": "100"})
				if carries {
					base.Header.Set(pairs[n/2].Name, pairs[n/2].Value)
				}
				w := httptest.NewRecorder()
				b.ReportAllocs()
				b.ResetTimer()
				for i = 0; i < b.N; i++ {
					r := *base
					r.Header = base.Header.Clone()
					rr, _ := withDefenseSnapshotHolder(&r)
					if err := privacy.ServeHTTP(w, rr, next); err != nil {
						b.Fatal(err)
					}
				}
				_ = sink
			})
		}
	}
}

// The per-request floor both families above pay: header clone and holder.
func BenchmarkDefenseEvidenceRequestFloor(b *testing.B) {
	base := benchBrowserRequest(map[string]any{"vhost_id": "100"})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := *base
		r.Header = base.Header.Clone()
		_, _ = withDefenseSnapshotHolder(&r)
	}
}

func benchPrivacyPairs(n int) []managedHeaderCredential {
	pairs := make([]managedHeaderCredential, n)
	for i := range pairs {
		pairs[i] = managedHeaderCredential{Name: fmt.Sprintf("X-Partner-Key-%03d", i), Value: fmt.Sprintf("partner-secret-%03d-0123456789abcdef", i)}
	}
	return pairs
}

// Redact on a request that carries no managed value scans the finding text
// for any managed value; this is the per-finding cost of that scan.
func BenchmarkManagedHeaderPrivacyRedactText(b *testing.B) {
	text := "Matched Data: union select found within ARGS:q: " + strings.Repeat("1 union select password from users where name='admin' -- ", 16)
	for _, n := range []int{8, 128} {
		b.Run(fmt.Sprintf("names=%d/bytes=%d", n, len(text)), func(b *testing.B) {
			state := newManagedHeaderState(compileManagedHeaderPolicy(benchPrivacyPairs(n)), nil)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if state.redact(text) == "" {
					b.Fatal("ordinary text was masked")
				}
			}
		})
	}
}

// The Header-derived identity request telemetry records (User-Agent,
// forwarded IP, hash IP), checked against the managed values.
func BenchmarkTelemetryIdentity(b *testing.B) {
	for _, n := range []int{0, 8, 128} {
		b.Run(fmt.Sprintf("names=%d", n), func(b *testing.B) {
			r := benchBrowserRequest(map[string]any{})
			r, _ = withDefenseSnapshotHolder(r)
			if n > 0 {
				requestDefenseHolder(r).capturePrivacy(compileManagedHeaderPolicy(benchPrivacyPairs(n)), r.Header)
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if telemetryIdentity(r).userAgent == "" {
					b.Fatal("no User-Agent")
				}
			}
		})
	}
}
