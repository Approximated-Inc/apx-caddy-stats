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

func privacyRegistrySize() int { return corazaPrivacyRegistry.len() }

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
			require.True(t, events[0].RuleMsg == managedHeaderMaskedText, "message was not masked before truncation")
			require.True(t, events[0].MatchData == managedHeaderMaskedText, "match data was not masked before truncation")
			require.True(t, events[1].RuleMsg == managedHeaderMaskedText && events[1].MatchData == managedHeaderMaskedText, "credential-bearing secondary text was retained")
		}
	}
	al := buildAuditLog(1700000000000000000, "missing-binding", "host", false, nil, &fakeMsgData{id: 920274, msg: secret, data: secret})
	al.tx.(*fakeTx).producer = fakeProducer{components: []string{managedHeaderPrivacySignature}}
	events := buildCorazaEvents(al)
	require.Len(t, events, 1)
	require.True(t, events[0].RuleMsg == managedHeaderMaskedText, "an unbound transaction's message was not masked")
	require.True(t, events[0].MatchData == managedHeaderMaskedText, "an unbound transaction's match data was not masked")
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

// The mask itself must never be, or contain, a managed value.
func TestManagedHeaderPrivacyMaskNeverCarriesAValue(t *testing.T) {
	for _, value := range []string{"REDACTED", "[REDACTED]", "writer-key!", managedHeaderMaskedText, "masked: managed header", "[masked]", managedHeaderMaskedIP} {
		r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: value}}, http.Header{"X-Key": {value}})
		bridge := &CorazaPrivacyBridge{}
		id := "privacy-marker-" + value
		release := bridge.Bind(id, r)
		require.True(t, bridge.Redact(id, "matched="+value) == "", "carried text was not masked")
		al := buildAuditLog(1700000000000000000, id, "host", false, nil, &fakeMsgData{id: 920274, msg: "matched=" + value, data: value})
		al.tx.(*fakeTx).producer = fakeProducer{components: []string{managedHeaderPrivacySignature}}
		events := buildCorazaEvents(al)
		release()
		require.Len(t, events, 1)
		policy := requestManagedHeaderState(r).policy
		for _, text := range []string{events[0].RuleMsg, events[0].MatchData} {
			require.True(t, text == "" || (!policy.equalsValue(text) && !policy.contain.find(text) && !strings.Contains(text, value)), "the mask token carried a managed value")
		}
		identity := telemetryIdentity(privacyRequestWith(t, []managedHeaderCredential{{Name: "User-Agent", Value: value}, {Name: "X-Forwarded-For", Value: value}}, http.Header{"User-Agent": {value}, "X-Forwarded-For": {value}}))
		require.True(t, identity.userAgent != value && !strings.Contains(identity.userAgent, value), "the User-Agent mask carried a managed value")
		require.True(t, identity.forwardedIP != value, "the forwarded IP mask carried a managed value")
	}
}

func privacyRequestWith(t *testing.T, pairs []managedHeaderCredential, headers http.Header) *http.Request {
	t.Helper()
	r := privacyRequest(t, pairs, headers)
	r.RemoteAddr = "203.0.113.7:41234"
	return r
}

func TestManagedHeaderPrivacyRegistryUnboundedAndCleanup(t *testing.T) {
	registry := newManagedHeaderRegistry()
	bridge := &CorazaPrivacyBridge{registry: registry}
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "abcd"}}, http.Header{"X-Key": {"abcd"}})
	releases := []func(){bridge.Bind("bound-a", r), bridge.Bind("bound-b", r), bridge.Bind("bound-c", r)}
	for _, id := range []string{"bound-a", "bound-b", "bound-c"} {
		require.True(t, bridge.bound(id), "a binding was refused")
		require.True(t, bridge.Redact(id, "abcd") == "", "managed text was not masked")
	}
	require.Equal(t, 3, registry.len())
	for _, release := range releases {
		release()
		release()
	}
	require.Zero(t, registry.len())
	require.False(t, bridge.bound("bound-a"), "a released binding stayed bound")
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

// Ordinary and carrying requests bind concurrently; each keeps its own decision.
func TestManagedHeaderPrivacyConcurrentMixedBindings(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Key", Value: "mixed-race-key!"}}
	bridge := &CorazaPrivacyBridge{}
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			carrying := i%2 == 0
			headers := http.Header{"X-Key": {"other"}}
			if carrying {
				headers = http.Header{"X-Key": {"mixed-race-key!"}}
			}
			r := privacyRequest(t, pairs, headers)
			id := fmt.Sprintf("privacy-mixed-%d", i)
			release := bridge.Bind(id, r)
			defer release()
			if got := bridge.Redact(id, "ordinary finding"); (got == "") != carrying {
				t.Error("a concurrent binding took another request's decision")
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
	text := strings.Repeat("x", 1<<19)
	require.True(t, bridge.Redact("budget-a", text) == "", "first WAF retained text")
	require.True(t, bridge.Redact("budget-b", text) == "", "privacy fallback retained text")
	require.True(t, bridge.Redact("budget-a", "small ordinary field") == "", "privacy fallback retained text")
}

func TestManagedHeaderPrivacyUnknownProofMasksWithoutChangingEvidence(t *testing.T) {
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "known-key!"}}, http.Header{"X-Key": {"other"}})
	bridge := &CorazaPrivacyBridge{}
	release := bridge.Bind("unknown-privacy-proof", r)
	defer release()
	al := buildAuditLog(1700000000000000000, "unknown-privacy-proof", "host", true, map[string][]string{"X-Apx-L7-Header-Exempt": {"true"}}, &fakeMsgData{id: 920274, msg: "ordinary text", data: "future unknown private material"})
	al.tx.(*fakeTx).producer = fakeProducer{components: []string{corazaHeaderExemptionSignature, managedHeaderPrivacySignature, "APX_MANAGED_HEADER_PRIVACY/2"}}
	events := buildCorazaEvents(al)
	require.Len(t, events, 1)
	require.Equal(t, managedHeaderMaskedText, events[0].RuleMsg)
	require.Equal(t, managedHeaderMaskedText, events[0].MatchData)
	require.True(t, events[0].WasBlocked)
	require.True(t, events[0].DefenseExempt)
}

func residualCRS920274(t *testing.T, writer, id, credential, supplied string, injectLate bool) []corazaDetection {
	t.Helper()
	collector := new(evidenceAuditCollector)
	plugins.RegisterAuditLogWriter(writer, func() plugintypes.AuditLogWriter { return collector })
	headers := http.Header{"X-Key": {supplied}}
	if injectLate {
		headers = nil
	}
	request := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: credential}}, headers)
	if injectLate {
		request.Header = http.Header{"X-Key": {supplied}}
	}
	release := (&CorazaPrivacyBridge{}).Bind(id, request)
	defer release()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`SecRuleEngine DetectionOnly
SecDefaultAction "phase:1,pass,log,auditlog"
SecAuditEngine On
SecAuditLogType ` + writer + `
SecAuditLogParts ABHIJKZ
SecComponentSignature "APX_MANAGED_HEADER_PRIVACY/1"
SecRule REQUEST_HEADERS:X-Key "@validateByteRange 32,34,38,42-59,61,65-90,95,97-122" "id:920274,phase:1,block,t:none,t:urlDecodeUni,msg:'Invalid character in request headers (outside of very strict set)',logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"
`))
	if err != nil {
		t.Fatal("WAF setup failed")
	}
	tx := waf.NewTransactionWithID(id)
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
	if events[0].WasBlocked || events[0].DefenseExempt {
		t.Fatal("DetectionOnly numeric/evidence semantics changed")
	}
	return events
}

func TestManagedHeaderPrivacyURLDecodeCRS920274(t *testing.T) {
	events := residualCRS920274(t, "residual_transformed_credentials", "residual-url-decode", "encoded-review-key%21", "encoded-review-key%21", false)
	if events[0].RuleMsg != managedHeaderMaskedText || events[0].MatchData != managedHeaderMaskedText {
		t.Fatal("credential-bearing actual920274 text was not completely masked")
	}
}

func TestManagedHeaderPrivacyURLDecodeSuppliedCredentialCRS920274(t *testing.T) {
	events := residualCRS920274(t, "residual_supplied_transformed_credentials", "residual-supplied-url-decode", "supplied-review-key!", "supplied-review-key%21", false)
	if events[0].RuleMsg != managedHeaderMaskedText || events[0].MatchData != managedHeaderMaskedText {
		t.Fatal("credential-bearing actual920274 text was not completely masked")
	}
}

func TestManagedHeaderPrivacyLateInjectedCRS920274(t *testing.T) {
	events := residualCRS920274(t, "residual_late_injected_credentials", "residual-late-injected", "late-review-key!", "late-review-key!", true)
	if events[0].RuleMsg != managedHeaderMaskedText || events[0].MatchData != managedHeaderMaskedText {
		t.Fatal("credential-bearing actual920274 text was not completely masked")
	}
}

// An ordinary value under a managed name is not the managed value: its
// finding keeps its detail, exactly as an unmanaged Header's would.
func TestManagedHeaderPrivacyOrdinaryValueUnderManagedNameCRS920274(t *testing.T) {
	events := residualCRS920274(t, "residual_ordinary_value", "residual-ordinary-value", "partner-review-key!", "someone-else!", false)
	if events[0].RuleMsg == managedHeaderMaskedText || events[0].MatchData != "REQUEST_HEADERS:X-Key=someone-else!" {
		t.Fatal("an ordinary value under a managed name lost its finding detail")
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

func TestManagedHeaderPrivacyInvalidTransactionIDsFailClosed(t *testing.T) {
	registry := newManagedHeaderRegistry()
	bridge := &CorazaPrivacyBridge{registry: registry}
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "not-supplied-key!"}}, nil)
	release := bridge.Bind("ordinary-admitted", r)
	require.True(t, bridge.Redact("ordinary-admitted", "ordinary") == "ordinary", "admitted non-sensitive request lost detail")
	for _, id := range []string{"", strings.Repeat("x", 129)} {
		invalid := bridge.Bind(id, r)
		require.True(t, bridge.Redact(id, "ordinary") == "", "invalid ID did not fail closed")
		invalid()
	}
	require.Equal(t, 1, registry.len())
	release()
	release()
	require.Zero(t, registry.len())
	require.True(t, bridge.Redact("ordinary-admitted", "ordinary") == "", "released binding retained text")
	// A WAF bound without any captured privacy state masks everything.
	bare := httptest.NewRequest("GET", "http://example.test/", nil)
	release = bridge.Bind("no-capture", bare)
	require.True(t, bridge.Redact("no-capture", "ordinary") == "", "a request without captured state was not masked")
	release()
}

// Only the managed value masks; another value under a managed name does not.
func TestManagedHeaderPrivacyManagedNameWithOtherValueKeepsDetail(t *testing.T) {
	for _, tc := range []struct {
		headers http.Header
		masked  bool
	}{
		{http.Header{"x-key": {"wrong-value"}}, false},
		{http.Header{"X-KEY": {"wrong", "another"}}, false},
		{http.Header{"X-Key": {"prefix-Case-Key!"}}, false},
		{http.Header{"X-Key": {"case-key!"}}, true},
		{http.Header{"X-Key": {"wrong", "CASE-KEY!"}}, true},
	} {
		r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "Case-Key!"}}, tc.headers)
		bridge := &CorazaPrivacyBridge{}
		release := bridge.Bind("privacy-name-envelope", r)
		got := bridge.Redact("privacy-name-envelope", "ordinary-looking finding")
		require.True(t, (got == "") == tc.masked, "masking did not follow the carried value")
		require.Nil(t, requestDefenseHolder(r).snapshot, "privacy became evidence authority")
		release()
	}
}

func TestManagedHeaderPrivacyGenerationPolicyAndMonotonicMutation(t *testing.T) {
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Old", Value: "old-private!"}}, nil)
	next := &DefenseEvidenceHandler{Mode: "capture_privacy", ManagedHeaders: []managedHeaderCredential{{Name: "X-New", Value: "new-private!"}}}
	require.NoError(t, next.Validate())
	r.Header = http.Header{"X-New": {"new-private!"}}
	require.NoError(t, next.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })))
	bridge := &CorazaPrivacyBridge{}
	a := bridge.Bind("generation-names-a", r)
	defer a()
	require.True(t, bridge.Redact("generation-names-a", "ordinary") == "ordinary", "a later generation replaced the original policy")
	r.Header = http.Header{"x-old": {"old-private!"}}
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

func TestManagedHeaderFieldDecoding(t *testing.T) {
	policy := compileManagedHeaderPolicy([]managedHeaderCredential{{Name: "X-Key", Value: "Key: a+b/c!"}, {Name: "X-Short", Value: "on"}})
	for i, tc := range []struct {
		field   string
		carries bool
	}{
		{"Key: a+b/c!", true},
		{"key: A+B/C!", true},
		{"  Key: a+b/c!\t", true},
		{"Key%3A%20a%2Bb%2Fc%21", true},
		{"Key%253A%2520a%252Bb%252Fc%2521", true},
		{"Key:%u0020a%u002bb%uff0fc%u0021", true},
		{"Key&#58; a&#43;b&#x2f;c&excl;", true},
		{"Key: a%00+b/c!", false}, // urlDecodeUni turns + into a space
		{"Key: a%2B%00b/c!", true},
		{"Key: a+b/c! extra", false},
		{"Key: a+b/c", false},
		{"on", true},
		{"ON", true},
		{"option", false},
		{"", false},
	} {
		require.Equal(t, tc.carries, policy.fieldCarries(tc.field), "case %d", i)
	}
	require.True(t, policy.contain.find("prefix KEY: A+B/C! suffix"))
	require.False(t, policy.contain.find("session on"), "a short value matched inside text")
	require.False(t, policy.contain.find("Key: a+b/"))

	ips := compileManagedHeaderPolicy([]managedHeaderCredential{{Name: "X-Forwarded-For", Value: "2001:DB8::17"}, {Name: "Cf-Connecting-Ip", Value: "198.51.100.23, 198.51.100.24"}})
	for i, tc := range []struct {
		field   string
		carries bool
	}{
		{"2001:db8::17", true},
		{"2001:0db8:0:0::17", true},
		{"203.0.113.5, 2001:db8::17", true},
		{"2001:db8::17 ,203.0.113.5", true},
		{"::ffff:198.51.100.24", true},
		{"198.51.100.23, 198.51.100.24", true},
		{"198.51.100.25", false},
		{"2001:db8::18, 203.0.113.5", false},
		{"2001%3Adb8%3A%3A17", true},
	} {
		require.Equal(t, tc.carries, ips.fieldCarries(tc.field), "IP case %d", i)
	}
	require.True(t, ips.managedIP("198.51.100.23") && !ips.managedIP("198.51.100.25") && !ips.managedIP("not-an-ip"))
	require.Equal(t, managedHeaderMaskedIP, ips.maskedIP)
	require.Equal(t, "100::1", compileManagedHeaderPolicy([]managedHeaderCredential{{Name: "X-Forwarded-For", Value: "100::"}}).maskedIP)
}

// An X-Forwarded-For list carrying a managed IP masks the request's WAF text.
func TestManagedHeaderPrivacyForwardedListMasksWAFText(t *testing.T) {
	pairs := []managedHeaderCredential{{Name: "X-Forwarded-For", Value: "203.0.113.9"}}
	r := privacyRequest(t, pairs, http.Header{"X-Forwarded-For": {"198.51.100.1, 203.0.113.9"}})
	bridge := &CorazaPrivacyBridge{}
	release := bridge.Bind("forwarded-list", r)
	defer release()
	require.True(t, bridge.Redact("forwarded-list", "Matched Data: found within REQUEST_HEADERS") == "", "a forwarded list carrying a managed IP was not masked")
	ordinary := privacyRequest(t, pairs, http.Header{"X-Forwarded-For": {"198.51.100.1, 203.0.113.10"}})
	release = bridge.Bind("forwarded-list-ordinary", ordinary)
	defer release()
	require.True(t, bridge.Redact("forwarded-list-ordinary", "ordinary") == "ordinary", "an ordinary forwarded list was masked")
}
