package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/require"
)

// Removing the trusted marker read or merging its counter bucket must fail
// these tests: raw request headers alone can never grant an exemption.
func TestDefenseExemptionHandlerWire(t *testing.T) {
	for _, modeV2 := range []bool{false, true} {
		for _, tc := range []struct {
			name    string
			enabled bool
			marker  any
			want    bool
		}{
			{"true", true, "true", true},
			{"false", true, "false", false},
			{"absent_spoofed_header", true, nil, false},
			{"bool_is_not_string", true, true, false},
			{"uppercase", true, "TRUE", false},
			{"whitespace", true, " true", false},
			{"off", false, "true", false},
		} {
			t.Run(tc.name+map[bool]string{false: "_legacy", true: "_v2"}[modeV2], func(t *testing.T) {
				a := newTestApp(t, "http://unused", "key", func(a *StatsApp) {
					cfg, err := json.Marshal(map[string]bool{"defense_exemption_telemetry": tc.enabled})
					require.NoError(t, err)
					require.NoError(t, json.Unmarshal(cfg, a))
					a.hashSalt = "salt"
					a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: modeV2, MaxRows: 20}
				})
				h := &StatsHandler{app: a}
				r := newRequestWithReplacer("GET", "/same", "100", upstreamSelected("upstream:80"))
				r.Header.Set("X-Apx-L7-Header-Exempt", "true")
				require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					// Set after stats starts, and remove the upstream transport header.
					if tc.marker != nil {
						caddyhttp.SetVar(r.Context(), "apx_l7_header_exempt", tc.marker)
					}
					r.Header.Del("X-Apx-L7-Header-Exempt")
					return nextHandler(200).ServeHTTP(w, r)
				})))
				require.Equal(t, 1, a.counterCount())
				require.Equal(t, uint64(1), a.uniqueHashTotal())
				rows, overflow := a.requestEvents.drain()
				require.Zero(t, overflow)
				require.Len(t, rows, 1)
				body, err := encodeBatch(42, 0, a.countersSnapshot(), nil, nil, l4IpSnap{}, nil, nil, nil, nil, nil, rows)
				require.NoError(t, err)
				lines := strings.Split(strings.TrimSpace(gunzipString(t, body)), "\n")
				require.Len(t, lines, 2)
				for _, line := range lines {
					var got map[string]any
					require.NoError(t, json.Unmarshal([]byte(line), &got))
					if tc.want {
						require.Equal(t, true, got["defense_exempt"], line)
					} else {
						require.NotContains(t, got, "defense_exempt", line)
					}
				}
			})
		}
	}
}

func TestDefenseExemptionMixedCounterBuckets(t *testing.T) {
	a := newTestApp(t, "http://unused", "key", func(a *StatsApp) {
		require.NoError(t, json.Unmarshal([]byte(`{"defense_exemption_telemetry":true}`), a))
	})
	h := &StatsHandler{app: a}
	for _, marker := range []string{"true", "false", "true", "false"} {
		r := newRequestWithReplacer("GET", "/same", "100", upstreamSelected("upstream:80"))
		caddyhttp.SetVar(r.Context(), "apx_l7_header_exempt", marker)
		require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, nextHandler(200)))
	}
	require.Equal(t, 2, a.counterCount(), "exempt and ordinary requests need distinct keys")
	var total uint64
	var marked int
	for k, c := range a.countersSnapshot() {
		require.Equal(t, uint64(2), c.RequestCount)
		require.Equal(t, uint64(42), c.BytesOut)
		total += c.RequestCount
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		require.NoError(t, encodeRow(gz, 42, k, c))
		require.NoError(t, gz.Close())
		if strings.Contains(gunzipString(t, b.Bytes()), `"defense_exempt":true`) {
			marked++
		}
	}
	require.Equal(t, uint64(4), total)
	require.Equal(t, 1, marked)
}

func TestDefenseExemptionCorazaWire(t *testing.T) {
	al := buildAuditLog(1_700_000_000_000_000_000, "tx", "h", true, map[string][]string{"x-apx-l7-header-exempt": {"true"}}, &fakeMsgData{id: 942100}, &fakeMsgData{id: 942101})
	al.tx.(*fakeTx).producer = fakeProducer{components: []string{"APX_HEADER_EXEMPT_TELEMETRY/1"}}
	events := buildCorazaEvents(al)
	require.Len(t, events, 2, "exemption must retain every detection")
	for _, event := range events {
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		require.NoError(t, encodeCorazaDetectionRow(gz, event, 42))
		require.NoError(t, gz.Close())
		var got map[string]any
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(gunzipString(t, b.Bytes()))), &got))
		require.Equal(t, true, got["defense_exempt"])
		require.Equal(t, float64(1), got["was_blocked"])
	}
}

func TestDefenseExemptionCorazaMarkerValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		headers map[string][]string
		want    bool
	}{
		{"canonical", true, map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}}, true},
		{"mixed_case", true, map[string][]string{"x-APX-l7-HEADER-exempt": {"true"}}, true},
		{"false", true, map[string][]string{"X-Apx-L7-Header-Exempt": {"false"}}, false},
		{"disabled", false, map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}}, false},
		{"absent", true, nil, false},
		{"empty", true, map[string][]string{"X-Apx-L7-Header-Exempt": {""}}, false},
		{"no_values", true, map[string][]string{"X-Apx-L7-Header-Exempt": nil}, false},
		{"uppercase", true, map[string][]string{"X-Apx-L7-Header-Exempt": {"TRUE"}}, false},
		{"whitespace", true, map[string][]string{"X-Apx-L7-Header-Exempt": {" true "}}, false},
		{"comma_list", true, map[string][]string{"X-Apx-L7-Header-Exempt": {"true,true"}}, false},
		{"duplicate_true", true, map[string][]string{"X-Apx-L7-Header-Exempt": {"true", "true"}}, false},
		{"duplicate_conflicting", true, map[string][]string{"X-Apx-L7-Header-Exempt": {"true", "false"}}, false},
		{"duplicate_case_variants", true, map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}, "x-apx-l7-header-exempt": {"true"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := buildAuditLog(1_700_000_000_000_000_000, "tx", "h", false, tc.headers, &fakeMsgData{id: 942100})
			if tc.enabled {
				al.tx.(*fakeTx).producer = fakeProducer{components: []string{"APX_HEADER_EXEMPT_TELEMETRY/1"}}
			}
			events := buildCorazaEvents(al)
			require.Len(t, events, 1)
			require.Equal(t, tc.want, events[0].DefenseExempt)
			var b bytes.Buffer
			gz := gzip.NewWriter(&b)
			require.NoError(t, encodeCorazaDetectionRow(gz, events[0], 42))
			require.NoError(t, gz.Close())
			var got map[string]any
			require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(gunzipString(t, b.Bytes()))), &got))
			if tc.want {
				require.Equal(t, true, got["defense_exempt"])
			} else {
				require.NotContains(t, got, "defense_exempt")
			}
		})
	}
}

func TestDefenseExemptionFlushRetainsMarkersAndClearsWindow(t *testing.T) {
	type batchResult struct {
		rows []map[string]any
		err  error
	}
	batches := make(chan batchResult, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			batches <- batchResult{err: err}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer gz.Close()
		var rows []map[string]any
		decoder := json.NewDecoder(gz)
		for {
			var row map[string]any
			err = decoder.Decode(&row)
			if err == io.EOF {
				break
			}
			if err != nil {
				batches <- batchResult{err: err}
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			rows = append(rows, row)
		}
		batches <- batchResult{rows: rows}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	a := newTestApp(t, server.URL, "key", func(a *StatsApp) {
		require.NoError(t, json.Unmarshal([]byte(`{"defense_exemption_telemetry":true}`), a))
		a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: true, MaxRows: 20}
		a.cfg.corazaMaxEvents = 20
		a.hashSalt = "salt"
	})
	h := &StatsHandler{app: a}
	for window, marker := range []string{"true", "false"} {
		r := newRequestWithReplacer("GET", "/same", "100", upstreamSelected("upstream:80"))
		require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			caddyhttp.SetVar(r.Context(), "apx_l7_header_exempt", marker)
			return nextHandler(200).ServeHTTP(w, r)
		})))
		al := buildAuditLog(1_700_000_000_000_000_000, "tx", "h", false, map[string][]string{"X-Apx-L7-Header-Exempt": {marker}}, &fakeMsgData{id: 942100})
		al.tx.(*fakeTx).producer = fakeProducer{components: []string{"APX_HEADER_EXEMPT_TELEMETRY/1"}}
		for _, event := range buildCorazaEvents(al) {
			a.RecordCorazaDetection(event)
		}
		require.Positive(t, a.memGov.bufferBytes.Load())
		a.flushOnce(0)
		var batch batchResult
		select {
		case batch = <-batches:
		default:
			t.Fatal("flush did not deliver a telemetry batch")
		}
		require.NoError(t, batch.err)
		rows := batch.rows
		require.Len(t, rows, 4, "counter, uniques, request log and WAF detection must all ship")
		seen := map[string]bool{}
		for _, row := range rows {
			kind := row["_type"].(string)
			seen[kind] = true
			if kind == "uniques" || window == 1 {
				require.NotContains(t, row, "defense_exempt")
			} else {
				require.Equal(t, true, row["defense_exempt"])
			}
		}
		require.True(t, seen["counter"])
		require.True(t, seen["uniques"])
		require.True(t, seen["request_event"])
		require.True(t, seen["coraza_detection"])
		require.Zero(t, a.counterCount())
		require.Zero(t, a.uniqueHashTotal())
		require.Zero(t, a.memGov.bufferBytes.Load())
	}
}

func TestDefenseExemptionConcurrentBuckets(t *testing.T) {
	a := newTestApp(t, "http://unused", "key")
	normal := Key{TsUnixMin: 30_000_000, VhostID: 100, Method: "GET", Status: 200, Origin: OriginUpstream}
	exempt := normal
	exempt.DefenseExempt = true
	require.NotSame(t, a.shardForKey(normal), a.shardForKey(exempt), "exemption participates in shard hashing")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				a.Record(normal, CounterDelta{BytesIn: 1, BytesOut: 2, DurationUs: 3, LatBucket: 0})
				a.Record(exempt, CounterDelta{BytesIn: 1, BytesOut: 2, DurationUs: 3, LatBucket: 0})
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 2, a.counterCount())
	for _, k := range []Key{normal, exempt} {
		counter, ok := a.counterFor(k)
		require.True(t, ok)
		require.Equal(t, uint64(2000), counter.RequestCount)
		require.Equal(t, uint64(2000), counter.BytesIn)
		require.Equal(t, uint64(4000), counter.BytesOut)
		require.Equal(t, uint64(6000), counter.DurationUsSum)
		require.Equal(t, uint64(2000), counter.LatBuckets[0])
	}
}

// Embedded Coraza interfaces provide the methods the adapter never reads;
// the overrides below exercise the writer's real app config and adapters.
type exemptionAudit struct {
	plugintypes.AuditLog
	tx       plugintypes.AuditLogTransaction
	messages []plugintypes.AuditLogMessage
}

func (a exemptionAudit) Transaction() plugintypes.AuditLogTransaction { return a.tx }
func (a exemptionAudit) Messages() []plugintypes.AuditLogMessage      { return a.messages }

type exemptionTx struct {
	plugintypes.AuditLogTransaction
	req        plugintypes.AuditLogTransactionRequest
	components []string
	producer   plugintypes.AuditLogTransactionProducer
}

func (exemptionTx) UnixTimestamp() int64                              { return 1_700_000_000_000_000_000 }
func (exemptionTx) ID() string                                        { return "tx" }
func (exemptionTx) ServerID() string                                  { return "h" }
func (exemptionTx) ClientIP() string                                  { return "203.0.113.7" }
func (exemptionTx) IsInterrupted() bool                               { return true }
func (a exemptionTx) Request() plugintypes.AuditLogTransactionRequest { return a.req }

func (a exemptionTx) Producer() plugintypes.AuditLogTransactionProducer {
	if a.producer != nil {
		return a.producer
	}
	return &exemptionProducer{components: a.components}
}

type exemptionProducer struct {
	plugintypes.AuditLogTransactionProducer
	components []string
}

func (a *exemptionProducer) Rulesets() []string {
	if a == nil {
		return nil
	}
	return a.components
}

type exemptionReq struct {
	plugintypes.AuditLogTransactionRequest
	headers map[string][]string
}

func (exemptionReq) Method() string                 { return "GET" }
func (exemptionReq) URI() string                    { return "/x" }
func (a exemptionReq) Headers() map[string][]string { return a.headers }

type exemptionMessage struct{ plugintypes.AuditLogMessage }

func (exemptionMessage) Data() plugintypes.AuditLogMessageData { return exemptionMessageData{} }

type exemptionMessageData struct {
	plugintypes.AuditLogMessageData
}

func (exemptionMessageData) ID() int                      { return 942100 }
func (exemptionMessageData) Msg() string                  { return "matched" }
func (exemptionMessageData) Data() string                 { return "data" }
func (exemptionMessageData) Severity() types.RuleSeverity { return types.RuleSeverityCritical }
func (exemptionMessageData) Tags() []string               { return []string{"test"} }

func TestDefenseExemptionWriterSignedChains(t *testing.T) {
	// Write has an unavoidable process-global app pointer; pure builder tests
	// above never change it. This matches the existing writer lifecycle tests.
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "enabled", false: "disabled"}[enabled], func(t *testing.T) {
			a, cleanup := newCorazaTestApp(t, 10)
			defer cleanup()
			a.DefenseExemptionTelemetry = enabled
			var components []string
			if enabled {
				components = []string{"APX_HEADER_EXEMPT_TELEMETRY/1"}
			}
			al := exemptionAudit{tx: exemptionTx{components: components, req: exemptionReq{headers: map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}}}}, messages: []plugintypes.AuditLogMessage{exemptionMessage{}}}
			require.NoError(t, (&corazaAuditWriter{}).Write(al))
			events := a.corazaSnapshot()
			require.Len(t, events, 1)
			require.Equal(t, enabled, events[0].DefenseExempt)
			require.True(t, events[0].WasBlocked)
			require.Equal(t, uint32(942100), events[0].RuleID)
		})
	}
}

func TestDefenseExemptionChallengeEvidence(t *testing.T) {
	for _, tc := range []struct {
		name           string
		enabled        bool
		marker         string
		wantChallenges int
	}{
		{"exempt", true, "true", 0},
		{"ordinary", true, "false", 1},
		{"disabled", false, "true", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestApp(t, "http://unused", "key", func(a *StatsApp) {
				a.DefenseExemptionTelemetry = tc.enabled
				a.Ingest.RequestEvents = &RequestEventsConfig{Enabled: true, ModeV2: true, MaxRows: 20}
				a.hashSalt = "salt"
			})
			r := newRequestWithReplacer("GET", "/__apx_challenge/verify", "100", nil)
			require.NoError(t, (&StatsHandler{app: a}).ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				caddyhttp.SetVar(r.Context(), "apx_l7_header_exempt", tc.marker)
				caddyhttp.SetVar(r.Context(), "apx_challenge_outcome", "passed")
				caddyhttp.SetVar(r.Context(), "apx_verify_outcome", "passed")
				return nextHandler(200).ServeHTTP(w, r)
			})))
			require.Len(t, a.challengeSnapshot(), tc.wantChallenges, "exempt challenge outcomes must not feed Defense evidence")
			require.Len(t, a.edgeVerifySnapshot(), 1, "Edge Verify metrics remain ordinary analytics")
			require.Equal(t, 1, a.counterCount())
			require.Equal(t, uint64(1), a.uniqueHashTotal())
			rows, overflow := a.requestEvents.drain()
			require.Zero(t, overflow)
			require.Len(t, rows, 1)
			require.Equal(t, tc.enabled && tc.marker == "true", rows[0].DefenseExempt)
			require.Equal(t, dispChallengePassed, rows[0].Disposition)
		})
	}
}

func TestDefenseExemptionWriterHotReloadTransactionTrust(t *testing.T) {
	for _, tc := range []struct {
		name              string
		currentAppEnabled bool
		components        []string
		want              bool
	}{
		{"old_unsigned_transaction_new_enabled_app", true, nil, false},
		{"old_signed_transaction_new_disabled_app", false, []string{"APX_HEADER_EXEMPT_TELEMETRY/1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, cleanup := newCorazaTestApp(t, 10)
			defer cleanup()
			a.DefenseExemptionTelemetry = tc.currentAppEnabled
			al := exemptionAudit{tx: exemptionTx{components: tc.components, req: exemptionReq{headers: map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}}}}, messages: []plugintypes.AuditLogMessage{exemptionMessage{}}}
			require.NoError(t, (&corazaAuditWriter{}).Write(al))
			events := a.corazaSnapshot()
			require.Len(t, events, 1)
			require.Equal(t, tc.want, events[0].DefenseExempt, "trust must follow the WAF transaction, not the newest process-global app")
		})
	}
}

func TestDefenseExemptionCorazaTransactionSignature(t *testing.T) {
	for _, tc := range []struct {
		name     string
		producer corazaProducerView
		want     bool
	}{
		{"missing_producer", nil, false},
		{"empty_rulesets", fakeProducer{}, false},
		{"different_ruleset", fakeProducer{components: []string{"OWASP_CRS/4.18.0"}}, false},
		{"exact_signature", fakeProducer{components: []string{"APX_HEADER_EXEMPT_TELEMETRY/1"}}, true},
		{"among_other_rulesets", fakeProducer{components: []string{"OWASP_CRS/4.18.0", "APX_HEADER_EXEMPT_TELEMETRY/1"}}, true},
		{"different_version", fakeProducer{components: []string{"APX_HEADER_EXEMPT_TELEMETRY/2"}}, false},
		{"lowercase", fakeProducer{components: []string{"apx_header_exempt_telemetry/1"}}, false},
		{"leading_space", fakeProducer{components: []string{" APX_HEADER_EXEMPT_TELEMETRY/1"}}, false},
		{"trailing_space", fakeProducer{components: []string{"APX_HEADER_EXEMPT_TELEMETRY/1 "}}, false},
		{"comment_suffix", fakeProducer{components: []string{"APX_HEADER_EXEMPT_TELEMETRY/1 (unsigned)"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := buildAuditLog(1_700_000_000_000_000_000, "tx", "h", false, map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}}, &fakeMsgData{id: 942100})
			al.tx.(*fakeTx).producer = tc.producer
			events := buildCorazaEvents(al)
			require.Len(t, events, 1)
			require.Equal(t, tc.want, events[0].DefenseExempt)
		})
	}
}

func TestDefenseExemptionWriterTypedNilProducer(t *testing.T) {
	a, cleanup := newCorazaTestApp(t, 10)
	defer cleanup()
	a.DefenseExemptionTelemetry = true
	var producer *exemptionProducer
	al := exemptionAudit{tx: exemptionTx{producer: producer, req: exemptionReq{headers: map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}}}}, messages: []plugintypes.AuditLogMessage{exemptionMessage{}}}
	require.NoError(t, (&corazaAuditWriter{}).Write(al))
	events := a.corazaSnapshot()
	require.Len(t, events, 1)
	require.False(t, events[0].DefenseExempt)
}

func TestDefenseExemptionRealCorazaAuditAcrossHotReload(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		parts                           string
		signed, currentAppEnabled, want bool
	}{
		{"unsigned_old_chain_new_enabled_app", "ABIJKZ", false, true, false},
		{"signed_old_chain_new_disabled_app", "ABHIJKZ", true, false, true},
		{"signature_without_H_is_untrusted", "ABIJKZ", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldApp, cleanup := newCorazaTestApp(t, 10)
			defer cleanup()
			oldApp.DefenseExemptionTelemetry = !tc.currentAppEnabled
			directives := `SecRuleEngine DetectionOnly
SecAuditEngine On
SecAuditLogType apx_stats
SecAuditLogParts ` + tc.parts + `
SecRule REQUEST_URI "@unconditionalMatch" "id:942100,phase:1,pass,log,auditlog,msg:'test'"
`
			if tc.signed {
				directives += `SecComponentSignature "APX_HEADER_EXEMPT_TELEMETRY/1"` + "\n"
			}
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
			require.NoError(t, err)
			tx := waf.NewTransaction()
			defer tx.Close()
			tx.ProcessConnection("203.0.113.7", 1234, "127.0.0.1", 80)
			tx.ProcessURI("/same", "GET", "HTTP/1.1")
			tx.AddRequestHeader("X-Apx-L7-Header-Exempt", "true")
			tx.ProcessRequestHeaders()
			// Swap the actual published app after the old WAF processed headers.
			newApp, newCleanup := newCorazaTestApp(t, 10)
			defer newCleanup()
			newApp.DefenseExemptionTelemetry = tc.currentAppEnabled
			tx.ProcessLogging()
			events := newApp.corazaSnapshot()
			require.Len(t, events, 1)
			require.Equal(t, tc.want, events[0].DefenseExempt)
			require.Equal(t, uint32(942100), events[0].RuleID)
			require.Empty(t, oldApp.corazaSnapshot(), "current app is the buffer destination, never the source of transaction trust")
		})
	}
}
