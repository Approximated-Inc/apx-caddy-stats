package apxstats

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/stretchr/testify/require"
)

func TestDefenseEvidenceCorazaIndependent(t *testing.T) {
	for _, tc := range []struct {
		marker string
		want   []bool
	}{
		{`{"http":true,"coraza_all":false,"coraza_rule_ids":[]}`, []bool{false, false}},
		{`{"http":false,"coraza_all":false,"coraza_rule_ids":[942100]}`, []bool{true, false}},
		{`{"http":false,"coraza_all":true,"coraza_rule_ids":[]}`, []bool{true, true}},
	} {
		al := buildAuditLog(1700000000000000000, "tx", "h", false, map[string][]string{"X-Apx-Defense-Evidence": {tc.marker}}, &fakeMsgData{id: 942100}, &fakeMsgData{id: 942101})
		al.tx.(*fakeTx).producer = fakeProducer{components: []string{"APX_DEFENSE_EVIDENCE/2"}}
		events := buildCorazaEvents(al)
		require.Len(t, events, 2)
		for i, want := range tc.want {
			require.Equal(t, want, events[i].DefenseExempt)
		}
	}
}

func evidenceHandler(t *testing.T, config string) caddyhttp.MiddlewareHandler {
	t.Helper()
	info, err := caddy.GetModule("http.handlers.apx_defense_evidence")
	require.NoError(t, err)
	module := info.New()
	require.NoError(t, json.Unmarshal([]byte(config), module))
	if validator, ok := module.(caddy.Validator); ok {
		require.NoError(t, validator.Validate())
	}
	return module.(caddyhttp.MiddlewareHandler)
}

func TestDefenseEvidenceOuterCloneCapture(t *testing.T) {
	capture := evidenceHandler(t, `{"mode":"capture","http_var":"e_http","coraza_rule_vars":{"942100":"e_rule"},"observe_coraza_var":"e_observe","skip_coraza_rule_vars":{"942101":"e_skip"}}`)
	stamp := evidenceHandler(t, `{"mode":"stamp_waf"}`)
	for _, exempt := range []bool{false, true} {
		a := newTestApp(t, "http://unused", "key", func(a *StatsApp) {
			a.DefenseExemptionTelemetry = true
			a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: true, MaxRows: 20}
		})
		h := &StatsHandler{app: a}
		r := newRequestWithReplacer("GET", "/private", "100", upstreamSelected("u:80"))
		require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			r = r.Clone(r.Context())
			value := "false"
			if exempt {
				value = "true"
			}
			for _, name := range []string{"e_http", "e_rule", "e_observe", "e_skip"} {
				caddyhttp.SetVar(r.Context(), name, value)
			}
			return capture.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				lateValue := map[bool]string{true: "false", false: "true"}[exempt]
				caddyhttp.SetVar(r.Context(), "apx_l7_header_exempt", lateValue)
				for _, name := range []string{"e_http", "e_rule", "e_observe", "e_skip"} {
					caddyhttp.SetVar(r.Context(), name, lateValue)
				}
				caddyhttp.SetVar(r.Context(), "apx_challenge_outcome", "failed")
				for boundary := 0; boundary < 2; boundary++ {
					r.Header = http.Header{"x-apx-defense-evidence": {`{"http":true,"coraza_all":true,"coraza_rule_ids":[]}`}, "X-Apx-Coraza-Observe": {"true", "true"}, "X-Apx-Coraza-Skip-942100": {"true"}}
					require.NoError(t, stamp.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
						var marker map[string]any
						require.NoError(t, json.Unmarshal([]byte(r.Header.Get("X-Apx-Defense-Evidence")), &marker))
						require.Equal(t, exempt, marker["http"])
						require.Equal(t, false, marker["coraza_all"])
						require.Empty(t, r.Header.Values("X-Apx-Coraza-Skip-942100"))
						require.Equal(t, map[bool]string{true: "true", false: ""}[exempt], r.Header.Get("X-Apx-Coraza-Observe"))
						require.Equal(t, map[bool]string{true: "true", false: ""}[exempt], r.Header.Get("X-Apx-Coraza-Skip-942101"))
						al := buildAuditLog(1700000000000000000, "tx", "h", false, r.Header, &fakeMsgData{id: 942100}, &fakeMsgData{id: 942101})
						al.tx.(*fakeTx).producer = fakeProducer{components: []string{"APX_DEFENSE_EVIDENCE/2"}}
						events := buildCorazaEvents(al)
						require.Equal(t, exempt, events[0].DefenseExempt)
						require.False(t, events[1].DefenseExempt)
						return nil
					})))
					r.Header = nil
				}
				return nextHandler(200).ServeHTTP(w, r)
			}))
		})))
		for k := range a.countersSnapshot() {
			require.Equal(t, exempt, k.DefenseExempt)
		}
		rows, _ := a.requestEvents.drain()
		require.Len(t, rows, 1)
		require.Equal(t, exempt, rows[0].DefenseExempt)
		require.Equal(t, map[bool]int{true: 0, false: 1}[exempt], len(a.challengeSnapshot()))
	}
}

func TestDefenseEvidenceMalformedAndVersionProof(t *testing.T) {
	valid := `{"http":false,"coraza_all":true,"coraza_rule_ids":[]}`
	for _, tc := range []struct {
		name       string
		marker     []string
		other      map[string][]string
		components []string
		want       bool
	}{
		{"valid", []string{valid}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, true},
		{"nil_producer", []string{valid}, nil, nil, false},
		{"unsigned_forged", []string{valid}, nil, []string{"OWASP_CRS/4"}, false},
		{"missing_no_v1_fallback", nil, nil, []string{"APX_DEFENSE_EVIDENCE/2", "APX_HEADER_EXEMPT_TELEMETRY/1"}, false},
		{"duplicates", []string{valid, valid}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"case_duplicates", []string{valid}, map[string][]string{"x-apx-defense-evidence": {valid}}, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"unknown_version", []string{valid}, nil, []string{"APX_DEFENSE_EVIDENCE/3", "APX_HEADER_EXEMPT_TELEMETRY/1"}, false},
		{"unknown_field", []string{`{"http":false,"coraza_all":true,"coraza_rule_ids":[],"extra":1}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"duplicate_json_key", []string{`{"http":false,"coraza_all":false,"coraza_all":true,"coraza_rule_ids":[]}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"missing_http", []string{`{"coraza_all":true,"coraza_rule_ids":[]}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"null_bool", []string{`{"http":null,"coraza_all":true,"coraza_rule_ids":[]}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"string_bool", []string{`{"http":"false","coraza_all":true,"coraza_rule_ids":[]}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"null_selectors", []string{`{"http":false,"coraza_all":true,"coraza_rule_ids":null}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"invalid_crs", []string{`{"http":false,"coraza_all":true,"coraza_rule_ids":[942110]}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"inline_id", []string{`{"http":false,"coraza_all":true,"coraza_rule_ids":[1234]}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"unsorted", []string{`{"http":false,"coraza_all":true,"coraza_rule_ids":[942101,942100]}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"duplicate_ids", []string{`{"http":false,"coraza_all":true,"coraza_rule_ids":[942100,942100]}`}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"oversized", []string{strings.Repeat(" ", 10000) + valid}, nil, []string{"APX_DEFENSE_EVIDENCE/2"}, false},
		{"v1_retained", nil, nil, []string{"APX_HEADER_EXEMPT_TELEMETRY/1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}}
			if tc.marker != nil {
				headers["X-Apx-Defense-Evidence"] = tc.marker
			}
			for k, v := range tc.other {
				headers[k] = v
			}
			al := buildAuditLog(1700000000000000000, "tx", "h", false, headers, &fakeMsgData{id: 942100})
			if tc.components != nil {
				al.tx.(*fakeTx).producer = fakeProducer{components: tc.components}
			}
			require.Equal(t, tc.want, buildCorazaEvents(al)[0].DefenseExempt)
		})
	}
}

func TestDefenseEvidenceHolderOnlyAndMissingSnapshot(t *testing.T) {
	h := &StatsHandler{HolderOnly: true}
	require.NoError(t, h.Provision(caddy.Context{}), "holder_only must never resolve StatsApp or logger")
	stamp := evidenceHandler(t, `{"mode":"stamp_waf"}`)
	capture := evidenceHandler(t, `{"mode":"capture","http_var":"e_http","observe_coraza_var":"e_observe"}`)
	for _, monitor := range []bool{false, true} {
		r := newRequestWithReplacer("GET", "/", "100", nil)
		if monitor {
			r.Header.Set("apx-monitor", "true")
		}
		caddyhttp.SetVar(r.Context(), "e_http", "true")
		caddyhttp.SetVar(r.Context(), "e_observe", "true")
		require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			require.NotNil(t, requestDefenseHolder(r))
			return capture.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return stamp.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
					require.Equal(t, `{"http":true,"coraza_all":false,"coraza_rule_ids":[]}`, r.Header.Get(defenseEvidenceHeader))
					return nil
				}))
			}))
		})))
	}
	// A downstream capture cannot create authority without the outer holder.
	r := newRequestWithReplacer("GET", "/", "100", nil)
	caddyhttp.SetVar(r.Context(), "e_http", "true")
	caddyhttp.SetVar(r.Context(), "e_observe", "true")
	require.NoError(t, capture.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		r.Header.Set(defenseEvidenceHeader, `{"http":true,"coraza_all":true,"coraza_rule_ids":[]}`)
		r.Header.Set("X-Apx-Coraza-Observe", "true")
		return stamp.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
			require.Empty(t, r.Header.Get(defenseEvidenceHeader))
			require.Empty(t, r.Header.Get("X-Apx-Coraza-Observe"))
			return nil
		}))
	})))
	a := newTestApp(t, "http://unused", "key", func(a *StatsApp) {
		require.NoError(t, json.Unmarshal([]byte(`{"defense_policy_evidence_v2":true,"defense_exemption_telemetry":true}`), a))
		a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: true, MaxRows: 20}
	})
	r = newRequestWithReplacer("GET", "/", "100", nil)
	caddyhttp.SetVar(r.Context(), "apx_l7_header_exempt", "true")
	require.NoError(t, (&StatsHandler{app: a}).ServeHTTP(httptest.NewRecorder(), r, nextHandler(403)))
	for k := range a.countersSnapshot() {
		require.False(t, k.DefenseExempt)
	}
	rows, _ := a.requestEvents.drain()
	require.Len(t, rows, 1)
	require.False(t, rows[0].DefenseExempt)
}

func TestDefenseEvidenceFrozenPrivateCopies(t *testing.T) {
	holder := new(defenseSnapshotHolder)
	original := defenseSnapshot{Evidence: defenseEvidence{HTTP: true, CorazaRuleIDs: []uint32{942100}}, SkipCorazaRuleIDs: []uint32{942101}}
	require.NoError(t, holder.publish(original))
	original.Evidence.CorazaRuleIDs[0] = 942101
	original.SkipCorazaRuleIDs[0] = 942100
	got, ok := holder.load()
	require.True(t, ok)
	require.Equal(t, []uint32{942100}, got.Evidence.CorazaRuleIDs)
	require.Equal(t, []uint32{942101}, got.SkipCorazaRuleIDs)
	got.Evidence.CorazaRuleIDs[0] = 942101
	got.SkipCorazaRuleIDs[0] = 942100
	require.Error(t, holder.publish(defenseSnapshot{}))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, ok := holder.load()
			require.True(t, ok)
			require.True(t, s.Evidence.HTTP)
			require.Equal(t, []uint32{942100}, s.Evidence.CorazaRuleIDs)
			require.Equal(t, []uint32{942101}, s.SkipCorazaRuleIDs)
			s.Evidence.CorazaRuleIDs[0] = 942101
		}()
	}
	wg.Wait()
	// Repeated capture cannot substitute eligible/exempt authority.
	capture := evidenceHandler(t, `{"mode":"capture","http_var":"e_http"}`)
	r, _ := withDefenseSnapshotHolder(newRequestWithReplacer("GET", "/", "100", nil))
	caddyhttp.SetVar(r.Context(), "e_http", "false")
	require.NoError(t, capture.ServeHTTP(httptest.NewRecorder(), r, nextHandler(200)))
	caddyhttp.SetVar(r.Context(), "e_http", "true")
	require.NoError(t, capture.ServeHTTP(httptest.NewRecorder(), r, nextHandler(200)))
	s, ok := requestDefenseHolder(r).load()
	require.True(t, ok)
	require.False(t, s.Evidence.HTTP)
}

func TestDefenseEvidenceClosedConfigAndStrictVars(t *testing.T) {
	for _, config := range []string{`{"mode":"forged"}`, `{"mode":"stamp_waf","http_var":"late"}`, `{"mode":"capture","coraza_rule_vars":{"0942100":"x"}}`, `{"mode":"capture","skip_coraza_rule_vars":{"1234":"x"}}`, `{"mode":"capture","skip_coraza_rule_vars":{"942110":"x"}}`, `{"mode":"capture","coraza_rule_vars":{"942100":""}}`} {
		info, err := caddy.GetModule("http.handlers.apx_defense_evidence")
		require.NoError(t, err)
		module := info.New()
		require.NoError(t, json.Unmarshal([]byte(config), module))
		require.Error(t, module.(caddy.Validator).Validate())
	}
	capture := evidenceHandler(t, `{"mode":"capture","http_var":"e_http"}`)
	for _, value := range []any{true, "TRUE", " true", "true ", nil, "false", "true"} {
		r, _ := withDefenseSnapshotHolder(newRequestWithReplacer("GET", "/", "100", nil))
		if value != nil {
			caddyhttp.SetVar(r.Context(), "e_http", value)
		}
		r.Header = http.Header{"x-APX-Defense-Evidence": {"forged"}, "X-Apx-L7-Header-Exempt": {"true"}, "X-Apx-Coraza-Skip-942100": {"true"}}
		require.NoError(t, capture.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error { require.Empty(t, r.Header); return nil })))
		snapshot, ok := requestDefenseHolder(r).load()
		require.True(t, ok)
		require.Equal(t, value == "true", snapshot.Evidence.HTTP)
	}
}

// This writer exercises the real transaction adapters without publishing or
// mutating the process-global StatsApp. Each test's factory owns its buffer.
type evidenceAuditCollector struct {
	mu     sync.Mutex
	events []corazaDetection
}

func (*evidenceAuditCollector) Init(plugintypes.AuditLogConfig) error { return nil }
func (*evidenceAuditCollector) Close() error                          { return nil }
func (c *evidenceAuditCollector) Write(al plugintypes.AuditLog) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, buildCorazaEvents(auditLogAdapter{al})...)
	return nil
}
func (c *evidenceAuditCollector) drain() []corazaDetection {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := c.events
	c.events = nil
	return events
}

func TestDefenseEvidenceRealEdgeWAFPipeline(t *testing.T) {
	collector := new(evidenceAuditCollector)
	plugins.RegisterAuditLogWriter("apx_task6_pipeline", func() plugintypes.AuditLogWriter { return collector })
	directives := `SecRuleEngine On
SecAuditEngine On
SecAuditLogType apx_task6_pipeline
SecAuditLogParts ABHIJKZ
SecComponentSignature "APX_DEFENSE_EVIDENCE/2"
SecRule REQUEST_HEADERS:X-Apx-Coraza-Observe "@streq true" "id:9500003,phase:1,nolog,pass,t:none,ctl:ruleEngine=DetectionOnly"
SecRule REQUEST_HEADERS:X-Apx-Coraza-Skip-942100 "@streq true" "id:9600001,phase:1,nolog,pass,t:none,ctl:ruleRemoveById=942100"
SecRule REQUEST_URI "@unconditionalMatch" "id:942100,phase:1,pass,log,auditlog,msg:'first'"
SecRule REQUEST_URI "@unconditionalMatch" "id:942101,phase:1,pass,log,auditlog,msg:'second'"
SecRule REQUEST_URI "@unconditionalMatch" "id:949110,phase:2,deny,status:403,log,auditlog,msg:'enforcement'"
`
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	require.NoError(t, err)
	capture := evidenceHandler(t, `{"mode":"capture","http_var":"e_http","coraza_all_var":"e_all","coraza_rule_vars":{"942101":"e_rule"},"observe_coraza_var":"e_observe","skip_coraza_rule_vars":{"942100":"e_skip"}}`)
	stamp := evidenceHandler(t, `{"mode":"stamp_waf"}`)
	for _, tc := range []struct {
		name                               string
		http, all, selected, observe, skip bool
	}{
		{"eligible", false, false, false, false, false},
		{"missing_snapshot", false, false, false, false, false},
		{"HTTP_only_enforcing", true, false, false, false, false},
		{"selected_skip_and_evidence", false, false, true, false, true},
		{"all_WAF_evidence_enforcing", false, true, false, false, false},
		{"observe_findings_eligible", false, false, false, true, false},
		{"observe_and_HTTP_evidence", true, false, false, true, false},
	} {
		for _, mutation := range []string{"forge", "copy", "delete"} {
			t.Run(tc.name+"_"+mutation, func(t *testing.T) {
				a := newTestApp(t, "http://unused", "key", func(a *StatsApp) {
					require.NoError(t, json.Unmarshal([]byte(`{"defense_policy_evidence_v2":true}`), a))
					a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: true, MaxRows: 20}
				})
				r := newRequestWithReplacer("GET", "/private", "100", nil)
				variables := caddyhttp.VarsMiddleware{}
				for name, value := range map[string]bool{"e_http": tc.http, "e_all": tc.all, "e_rule": tc.selected, "e_observe": tc.observe, "e_skip": tc.skip} {
					variables[name] = map[bool]string{true: "true", false: "false"}[value]
				}
				edge := &headers.Handler{}
				config := `{"request":{"set":{"X-Apx-Defense-Evidence":["{\"http\":true,\"coraza_all\":true,\"coraza_rule_ids\":[942100]}"],"X-Apx-Coraza-Observe":["true"],"X-Apx-Coraza-Skip-942101":["true"]}}}`
				if mutation == "copy" {
					r.Header.Set("X-Attacker-Evidence", `{"http":true,"coraza_all":true,"coraza_rule_ids":[942100]}`)
					repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
					repl.Set("http.request.header.X-Attacker-Evidence", r.Header.Get("X-Attacker-Evidence"))
					config = `{"request":{"set":{"X-Apx-Defense-Evidence":["{http.request.header.X-Attacker-Evidence}"],"X-Apx-Coraza-Observe":["true"],"X-Apx-Coraza-Skip-942101":["true"]}}}`
				}
				if mutation == "delete" {
					config = `{"request":{"delete":["X-Apx-Defense-Evidence","X-Apx-Coraza-Observe","X-Apx-Coraza-Skip-*"]}}`
				}
				require.NoError(t, json.Unmarshal([]byte(config), edge))
				require.NoError(t, edge.Provision(caddy.Context{}))
				nativeWAF := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					tx := waf.NewTransaction()
					defer tx.Close()
					tx.ProcessConnection("203.0.113.7", 1234, "127.0.0.1", 80)
					tx.ProcessURI(r.URL.Path, r.Method, "HTTP/1.1")
					for name, values := range r.Header {
						for _, value := range values {
							tx.AddRequestHeader(name, value)
						}
					}
					require.Nil(t, tx.ProcessRequestHeaders())
					interruption, err := tx.ProcessRequestBody()
					require.NoError(t, err)
					require.Equal(t, !tc.observe, interruption != nil)
					tx.ProcessLogging()
					events := collector.drain()
					seen := map[uint32]bool{}
					for _, event := range events {
						seen[event.RuleID] = true
						require.Equal(t, tc.all || (tc.selected && event.RuleID == 942101), event.DefenseExempt)
						require.Equal(t, !tc.observe, event.WasBlocked)
					}
					require.Equal(t, !tc.skip, seen[942100])
					require.True(t, seen[942101])
					require.True(t, seen[949110])
					if interruption != nil {
						return caddyhttp.Error(403, errors.New("interruption triggered"))
					}
					w.WriteHeader(200)
					return nil
				})
				captureForCase := capture
				if tc.name == "missing_snapshot" {
					captureForCase = &StatsHandler{HolderOnly: true}
				}
				err = (&StatsHandler{app: a}).ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					return variables.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
						return captureForCase.ServeHTTP(w, r.Clone(r.Context()), caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
							return edge.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
								if mutation != "delete" {
									require.Equal(t, `{"http":true,"coraza_all":true,"coraza_rule_ids":[942100]}`, r.Header.Get(defenseEvidenceHeader))
									require.Equal(t, "true", r.Header.Get("X-Apx-Coraza-Observe"))
								}
								late := caddyhttp.VarsMiddleware{"e_http": "true", "e_all": "true", "e_rule": "true", "e_observe": "true", "e_skip": "true", "apx_l7_header_exempt": "true"}
								return late.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return stamp.ServeHTTP(w, r, nativeWAF) }))
							}))
						}))
					}))
				}))
				require.Equal(t, !tc.observe, err != nil)
				counters := a.countersSnapshot()
				require.Len(t, counters, 1)
				for k := range counters {
					require.Equal(t, tc.http, k.DefenseExempt)
					if !tc.observe {
						require.Equal(t, uint16(403), k.Status)
						require.Equal(t, OriginClusterBlocked, k.Origin)
					}
				}
				rows, _ := a.requestEvents.drain()
				require.Len(t, rows, 1)
				require.Equal(t, tc.http, rows[0].DefenseExempt)
			})
		}
	}
}

func TestDefenseEvidenceConcurrentRealOldNewTransactions(t *testing.T) {
	collector := new(evidenceAuditCollector)
	plugins.RegisterAuditLogWriter("apx_task6_reload", func() plugintypes.AuditLogWriter { return collector })
	var wafs []coraza.WAF
	for _, signature := range []string{"APX_HEADER_EXEMPT_TELEMETRY/1", "APX_DEFENSE_EVIDENCE/2"} {
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`SecRuleEngine DetectionOnly
SecAuditEngine On
SecAuditLogType apx_task6_reload
SecAuditLogParts ABHIJKZ
SecComponentSignature "` + signature + `"
SecRule REQUEST_URI "@unconditionalMatch" "id:942100,phase:1,pass,log,auditlog,msg:'test'"`))
		require.NoError(t, err)
		wafs = append(wafs, waf)
	}
	// Both old->new and new->old generation overlap; a transaction's proof
	// remains authoritative after the other WAF starts processing transactions.
	for _, order := range [][]int{{0, 1}, {1, 0}} {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			for _, generation := range order {
				wg.Add(1)
				go func(generation int) {
					defer wg.Done()
					tx := wafs[generation].NewTransaction()
					defer tx.Close()
					tx.ProcessConnection("203.0.113.7", 1234, "127.0.0.1", 80)
					tx.ProcessURI(map[int]string{0: "/old", 1: "/new"}[generation], "GET", "HTTP/1.1")
					tx.AddRequestHeader("X-Apx-L7-Header-Exempt", "true")
					tx.AddRequestHeader(defenseEvidenceHeader, `{"http":true,"coraza_all":false,"coraza_rule_ids":[]}`)
					tx.ProcessRequestHeaders()
					tx.ProcessLogging()
				}(generation)
			}
		}
		wg.Wait()
		events := collector.drain()
		require.Len(t, events, 200)
		counts := map[string]int{}
		for _, event := range events {
			require.Equal(t, event.RequestURI == "/old", event.DefenseExempt)
			counts[event.RequestURI]++
		}
		require.Equal(t, 100, counts["/old"])
		require.Equal(t, 100, counts["/new"])
	}
}
