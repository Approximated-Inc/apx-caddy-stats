package apxstats

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

func privacyRequest(t *testing.T, pairs []managedHeaderCredential, headers http.Header) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", "http://example.test/partial", nil)
	r.Header = headers
	r, _ = withDefenseSnapshotHolder(r)
	h := &DefenseEvidenceHandler{Mode: "capture_privacy", ManagedHeaders: pairs}
	require.NoError(t, h.Validate())
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })))
	return r
}

func TestManagedHeaderPrivacyOriginalDuplicatePartialAndMutation(t *testing.T) {
	secret := "original-key!"
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: secret}, {Name: "X-Other", Value: "other-key!"}},
		http.Header{"x-key": {"wrong", secret}, "X-KEY": {"prefix-" + secret}})
	r.Header = http.Header{"X-Key": {"changed"}}
	bridge := &CorazaPrivacyBridge{}
	release := bridge.Bind("privacy-original", r)
	defer release()
	require.True(t, bridge.Redact("privacy-original", "matched="+secret) == "", "sensitive original text was not masked")
	require.True(t, bridge.Redact("privacy-original", "ordinary") == "", "credential-bearing ordinary-looking text was retained")
	require.Nil(t, requestDefenseHolder(r).snapshot, "privacy must not publish evidence authority")
	require.False(t, strings.Contains(fmt.Sprint(r.Header), secret), "mutated Header retained original value")
}

func TestManagedHeaderPrivacyWriterBeforeTruncationPreservesRowsAndProof(t *testing.T) {
	secret := "writer-key!"
	for _, proof := range []string{corazaHeaderExemptionSignature, defenseEvidenceSignature} {
		for _, excluded := range []bool{false, true} {
			id := fmt.Sprintf("privacy-writer-%s-%v", proof, excluded)
			r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: secret}}, http.Header{"X-Key": {secret}})
			release := (&CorazaPrivacyBridge{}).Bind(id, r)
			headers := map[string][]string{"X-Apx-L7-Header-Exempt": {fmt.Sprint(excluded)}, "X-Apx-Defense-Evidence": {defenseEvidence{CorazaAll: excluded}.marker()}}
			al := buildAuditLog(1700000000000000000, id, "host", true, headers,
				&fakeMsgData{id: 920274, msg: strings.Repeat("m", corazaRuleMsgMaxBytes-4) + secret, data: strings.Repeat("d", corazaMatchDataMaxBytes-4) + secret},
				&fakeMsgData{id: 942100, msg: "independent finding", data: "ordinary"})
			al.tx.(*fakeTx).producer = fakeProducer{components: []string{proof, managedHeaderPrivacySignature}}
			events := buildCorazaEvents(al)
			release()
			require.Len(t, events, 2)
			require.EqualValues(t, 920274, events[0].RuleID)
			require.True(t, events[0].WasBlocked)
			require.Equal(t, excluded, events[0].DefenseExempt)
			require.True(t, events[0].RuleMsg == "", "message was not masked before truncation")
			require.True(t, events[0].MatchData == "", "match data was not masked before truncation")
			require.True(t, events[1].RuleMsg == "" && events[1].MatchData == "", "credential-bearing secondary text was retained")
		}
	}
	al := buildAuditLog(1700000000000000000, "missing-binding", "host", false, nil, &fakeMsgData{id: 920274, msg: secret, data: secret})
	al.tx.(*fakeTx).producer = fakeProducer{components: []string{managedHeaderPrivacySignature}}
	events := buildCorazaEvents(al)
	require.Len(t, events, 1)
	require.Empty(t, events[0].RuleMsg)
	require.Empty(t, events[0].MatchData)
	require.False(t, events[0].DefenseExempt)
}

func TestManagedHeaderPrivacyCollisionAndBothCloseOrders(t *testing.T) {
	for _, firstCloses := range []bool{true, false} {
		id := fmt.Sprintf("privacy-collision-%v", firstCloses)
		bridge := &CorazaPrivacyBridge{}
		a := bridge.Bind(id, privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "a-key!"}}, http.Header{"X-Key": {"a-key!"}}))
		b := bridge.Bind(id, privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "b-key!"}}, http.Header{"X-Key": {"b-key!"}}))
		require.True(t, bridge.Redact(id, "a-key! b-key!") == "", "privacy fallback retained text")
		if firstCloses {
			a()
		} else {
			b()
		}
		require.True(t, bridge.Redact(id, "a-key! b-key!") == "", "privacy fallback retained text")
		third := bridge.Bind(id, privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "c-key!"}}, http.Header{"X-Key": {"c-key!"}}))
		require.True(t, bridge.Redact(id, "a-key! b-key! c-key!") == "", "privacy fallback retained text")
		a()
		b()
		require.True(t, bridge.Redact(id, "a-key! b-key! c-key!") == "", "privacy fallback retained text")
		third()
		require.True(t, bridge.Redact(id, "a-key! b-key!") == "", "privacy fallback retained text")
	}
}

func TestManagedHeaderPrivacyEmptyMaskAndCaptureBudget(t *testing.T) {
	for _, value := range []string{"REDACTED", "[REDACTED]", "writer-key!"} {
		r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: value}}, http.Header{"X-Key": {value}})
		bridge := &CorazaPrivacyBridge{}
		id := "privacy-marker-" + value
		release := bridge.Bind(id, r)
		masked := bridge.Redact(id, "matched="+value)
		require.False(t, strings.Contains(masked, value), "mask token retained a managed value")
		release()
	}
	pairs := make([]managedHeaderCredential, 32768)
	for i := range pairs {
		pairs[i] = managedHeaderCredential{Name: fmt.Sprintf("X-Key-%d", i), Value: fmt.Sprintf("key-%d!", i)}
	}
	r := privacyRequest(t, pairs, http.Header{strings.Repeat("N", 128): {"ordinary"}})
	bridge := &CorazaPrivacyBridge{}
	release := bridge.Bind("privacy-work-overflow", r)
	defer release()
	require.True(t, bridge.Redact("privacy-work-overflow", "unrelated text") == "", "privacy fallback retained text")
}

func TestManagedHeaderPrivacyRegistryHardBoundsAndCleanup(t *testing.T) {
	registry := newManagedHeaderRegistry(2)
	bridge := &CorazaPrivacyBridge{registry: registry}
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "abcd"}}, http.Header{"X-Key": {"abcd"}})
	releases := []func(){bridge.Bind("bound-a", r), bridge.Bind("bound-b", r), bridge.Bind("bound-c", r)}
	require.True(t, bridge.Redact("bound-a", "abcd") == "", "managed text was not masked")
	require.True(t, bridge.Redact("bound-c", "abcd") == "", "privacy fallback retained text")
	require.Len(t, registry.entries, 2)
	for _, release := range releases {
		release()
		release()
	}
	require.Len(t, registry.entries, 0)
	release := bridge.Bind("bound-new", r)
	require.True(t, bridge.Redact("bound-new", "abcd") == "", "managed text was not masked")
	release()
}

func TestManagedHeaderPrivacyConcurrentBinding(t *testing.T) {
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "race-key!"}}, http.Header{"X-Key": {"race-key!"}})
	bridge := &CorazaPrivacyBridge{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("privacy-race-%d", i)
			release := bridge.Bind(id, r)
			defer release()
			if bridge.Redact(id, "race-key!") != "" {
				t.Error("credential was not masked")
			}
		}(i)
	}
	wg.Wait()
}

func TestManagedHeaderPrivacyMaskSharedAcrossWAFTransactions(t *testing.T) {
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "budget-key!"}}, http.Header{"X-Key": {"budget-key!"}})
	bridge := &CorazaPrivacyBridge{}
	a := bridge.Bind("budget-a", r)
	defer a()
	b := bridge.Bind("budget-b", r)
	defer b()
	text := strings.Repeat("x", managedHeaderWorkMaxBytes/2)
	require.True(t, bridge.Redact("budget-a", text) == "", "first WAF retained text")
	require.True(t, bridge.Redact("budget-b", text) == "", "privacy fallback retained text")
	require.True(t, bridge.Redact("budget-a", "small ordinary field") == "", "privacy fallback retained text")
}

func TestManagedHeaderPrivacyUnknownProofMasksWithoutChangingEvidence(t *testing.T) {
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "known-key!"}}, http.Header{"X-Key": {"known-key!"}})
	bridge := &CorazaPrivacyBridge{}
	release := bridge.Bind("unknown-privacy-proof", r)
	defer release()
	al := buildAuditLog(1700000000000000000, "unknown-privacy-proof", "host", true, map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}}, &fakeMsgData{id: 920274, msg: "ordinary text", data: "future unknown private material"})
	al.tx.(*fakeTx).producer = fakeProducer{components: []string{corazaHeaderExemptionSignature, managedHeaderPrivacySignature, "APX_MANAGED_HEADER_PRIVACY/2"}}
	events := buildCorazaEvents(al)
	require.Len(t, events, 1)
	require.Empty(t, events[0].RuleMsg)
	require.Empty(t, events[0].MatchData)
	require.True(t, events[0].WasBlocked)
	require.True(t, events[0].DefenseExempt)
}

func TestManagedHeaderPrivacyURLDecodeCRS920274(t *testing.T) {
	collector := new(evidenceAuditCollector)
	plugins.RegisterAuditLogWriter("residual_transformed_credentials", func() plugintypes.AuditLogWriter { return collector })
	credential := "encoded-review-key%21"
	request := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: credential}}, http.Header{"X-Key": {credential}})
	release := (&CorazaPrivacyBridge{}).Bind("residual-url-decode", request)
	defer release()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`SecRuleEngine DetectionOnly
SecDefaultAction "phase:1,pass,log,auditlog"
SecAuditEngine On
SecAuditLogType residual_transformed_credentials
SecAuditLogParts ABHIJKZ
SecComponentSignature "APX_MANAGED_HEADER_PRIVACY/1"
SecRule REQUEST_HEADERS:X-Key "@validateByteRange 32,34,38,42-59,61,65-90,95,97-122" "id:920274,phase:1,block,t:none,t:urlDecodeUni,msg:'Invalid character in request headers (outside of very strict set)',logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"
`))
	if err != nil {
		t.Fatal("WAF setup failed")
	}
	tx := waf.NewTransactionWithID("residual-url-decode")
	defer tx.Close()
	tx.ProcessConnection("203.0.113.7", 1234, "127.0.0.1", 80)
	tx.ProcessURI("/privacy", "GET", "HTTP/1.1")
	tx.AddRequestHeader("X-Key", credential)
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	events := collector.drain()
	if len(events) != 1 || events[0].RuleID != 920274 {
		t.Fatalf("expected actual920274 finding, got count=%d", len(events))
	}
	if events[0].RuleMsg != "" || events[0].MatchData != "" {
		t.Fatal("credential-bearing actual920274 text was not completely masked")
	}
	if events[0].WasBlocked || events[0].DefenseExempt {
		t.Fatal("DetectionOnly numeric/evidence semantics changed")
	}
}

func TestManagedHeaderPrivacyNoCapturedCredentialRetainsOrdinaryText(t *testing.T) {
	for _, headers := range []http.Header{nil, {"X-Other": {"Case-Key!"}}} {
		r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "Case-Key!"}}, headers)
		bridge := &CorazaPrivacyBridge{}
		release := bridge.Bind("privacy-ordinary", r)
		require.True(t, bridge.Redact("privacy-ordinary", "ordinary finding") == "ordinary finding", "non-sensitive request lost text detail")
		release()
	}
}

func TestManagedHeaderPrivacyOrdinaryRegistryExhaustionMasks(t *testing.T) {
	registry := newManagedHeaderRegistry(1)
	bridge := &CorazaPrivacyBridge{registry: registry}
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "not-supplied-key!"}}, nil)
	release := bridge.Bind("ordinary-admitted", r)
	require.True(t, bridge.Redact("ordinary-admitted", "ordinary") == "ordinary", "admitted non-sensitive request lost detail")
	overflow := bridge.Bind("ordinary-overflow", r)
	require.True(t, bridge.Redact("ordinary-overflow", "ordinary") == "", "registry overflow did not fail closed")
	for _, id := range []string{"", strings.Repeat("x", 129)} {
		invalid := bridge.Bind(id, r)
		require.True(t, bridge.Redact(id, "ordinary") == "", "invalid ID did not fail closed")
		invalid()
	}
	require.Len(t, registry.entries, 1)
	overflow()
	release()
	release()
	require.Len(t, registry.entries, 0)
	require.True(t, bridge.Redact("ordinary-admitted", "ordinary") == "", "released binding retained text")
}

func TestManagedHeaderPrivacyURLDecodeSuppliedCredentialCRS920274(t *testing.T) {
	collector := new(evidenceAuditCollector)
	plugins.RegisterAuditLogWriter("residual_supplied_transformed_credentials", func() plugintypes.AuditLogWriter { return collector })
	credential := "supplied-review-key!"
	supplied := "supplied-review-key%21"
	request := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: credential}}, http.Header{"X-Key": {supplied}})
	release := (&CorazaPrivacyBridge{}).Bind("residual-supplied-url-decode", request)
	defer release()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`SecRuleEngine DetectionOnly
SecDefaultAction "phase:1,pass,log,auditlog"
SecAuditEngine On
SecAuditLogType residual_supplied_transformed_credentials
SecAuditLogParts ABHIJKZ
SecComponentSignature "APX_MANAGED_HEADER_PRIVACY/1"
SecRule REQUEST_HEADERS:X-Key "@validateByteRange 32,34,38,42-59,61,65-90,95,97-122" "id:920274,phase:1,block,t:none,t:urlDecodeUni,msg:'Invalid character in request headers (outside of very strict set)',logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"
`))
	if err != nil {
		t.Fatal("WAF setup failed")
	}
	tx := waf.NewTransactionWithID("residual-supplied-url-decode")
	defer tx.Close()
	tx.ProcessConnection("203.0.113.7", 1234, "127.0.0.1", 80)
	tx.ProcessURI("/privacy", "GET", "HTTP/1.1")
	tx.AddRequestHeader("X-Key", supplied)
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	events := collector.drain()
	if len(events) != 1 || events[0].RuleID != 920274 {
		t.Fatalf("expected actual920274 finding, got count=%d", len(events))
	}
	if events[0].RuleMsg != "" || events[0].MatchData != "" {
		t.Fatal("credential-bearing actual920274 text was not completely masked")
	}
	if events[0].WasBlocked || events[0].DefenseExempt {
		t.Fatal("DetectionOnly numeric/evidence semantics changed")
	}
}

func TestManagedHeaderPrivacySensitiveNameMasksRegardlessOfValue(t *testing.T) {
	for _, headers := range []http.Header{{"x-key": {"wrong-value"}}, {"X-KEY": {"wrong", "another"}}, {"X-Key": {"case-key!"}}} {
		r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "Case-Key!"}}, headers)
		bridge := &CorazaPrivacyBridge{}
		release := bridge.Bind("privacy-name-envelope", r)
		require.True(t, bridge.Redact("privacy-name-envelope", "ordinary-looking finding") == "", "sensitive Header container retained text")
		require.Nil(t, requestDefenseHolder(r).snapshot, "privacy became evidence authority")
		release()
	}
}

func TestManagedHeaderPrivacyLateInjectedCRS920274(t *testing.T) {
	collector := new(evidenceAuditCollector)
	plugins.RegisterAuditLogWriter("residual_late_injected_credentials", func() plugintypes.AuditLogWriter { return collector })
	credential := "late-review-key!"
	supplied := credential
	request := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: credential}}, nil)
	request.Header = http.Header{"X-Key": {supplied}}
	release := (&CorazaPrivacyBridge{}).Bind("residual-late-injected", request)
	defer release()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`SecRuleEngine DetectionOnly
SecDefaultAction "phase:1,pass,log,auditlog"
SecAuditEngine On
SecAuditLogType residual_late_injected_credentials
SecAuditLogParts ABHIJKZ
SecComponentSignature "APX_MANAGED_HEADER_PRIVACY/1"
SecRule REQUEST_HEADERS:X-Key "@validateByteRange 32,34,38,42-59,61,65-90,95,97-122" "id:920274,phase:1,block,t:none,t:urlDecodeUni,msg:'Invalid character in request headers (outside of very strict set)',logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"
`))
	if err != nil {
		t.Fatal("WAF setup failed")
	}
	tx := waf.NewTransactionWithID("residual-late-injected")
	defer tx.Close()
	tx.ProcessConnection("203.0.113.7", 1234, "127.0.0.1", 80)
	tx.ProcessURI("/privacy", "GET", "HTTP/1.1")
	tx.AddRequestHeader("X-Key", supplied)
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	events := collector.drain()
	if len(events) != 1 || events[0].RuleID != 920274 {
		t.Fatalf("expected actual920274 finding, got count=%d", len(events))
	}
	if events[0].RuleMsg != "" || events[0].MatchData != "" {
		t.Fatal("credential-bearing actual920274 text was not completely masked")
	}
	if events[0].WasBlocked || events[0].DefenseExempt {
		t.Fatal("DetectionOnly numeric/evidence semantics changed")
	}
}

func TestManagedHeaderPrivacyWorkSharedWithBinds(t *testing.T) {
	pairs := make([]managedHeaderCredential, managedHeaderPairMaxCount)
	for i := range pairs {
		pairs[i] = managedHeaderCredential{Name: fmt.Sprintf("X-N-%05d", i), Value: "unused"}
	}
	r := privacyRequest(t, pairs, http.Header{"X-Other": {"ordinary"}})
	bridge := &CorazaPrivacyBridge{}
	a := bridge.Bind("shared-work-a", r)
	defer a()
	require.True(t, bridge.Redact("shared-work-a", "ordinary") == "ordinary", "within-budget non-sensitive request lost detail")
	b := bridge.Bind("shared-work-b", r)
	defer b()
	require.True(t, bridge.Redact("shared-work-b", "ordinary") == "", "shared capture/Bind budget did not mask")
	require.True(t, bridge.Redact("shared-work-a", "ordinary") == "", "budget masking was not shared with earlier bindings")
}

func TestManagedHeaderPrivacyGenerationNamesAndMonotonicMutation(t *testing.T) {
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Old", Value: "old-private!"}}, nil)
	next := &DefenseEvidenceHandler{Mode: "capture_privacy", ManagedHeaders: []managedHeaderCredential{{Name: "X-New", Value: "new-private!"}}}
	require.NoError(t, next.Validate())
	require.NoError(t, next.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })))
	bridge := &CorazaPrivacyBridge{}
	r.Header = http.Header{"X-New": {"ordinary"}}
	a := bridge.Bind("generation-names-a", r)
	defer a()
	require.True(t, bridge.Redact("generation-names-a", "ordinary") == "ordinary", "a later generation replaced the original private name reference")
	r.Header = http.Header{"x-old": {"wrong-value"}}
	b := bridge.Bind("generation-names-b", r)
	defer b()
	r.Header = nil
	c := bridge.Bind("generation-names-c", r)
	defer c()
	for _, id := range []string{"generation-names-a", "generation-names-b", "generation-names-c"} {
		require.True(t, bridge.Redact(id, "ordinary-looking text") == "", "later deletion or binding reverted privacy masking")
	}
	require.Nil(t, requestDefenseHolder(r).snapshot, "privacy mutation granted evidence authority")
}
