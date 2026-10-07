package apxstats

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

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
	require.True(t, bridge.Redact("privacy-original", "matched="+secret) == "[REDACTED]", "sensitive original text was not masked")
	require.Equal(t, "ordinary", bridge.Redact("privacy-original", "ordinary"))
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
			headers := map[string][]string{"X-Apx-L7-Header-Exempt": {fmt.Sprint(excluded)}, "X-Apx-Defense-Evidence": {fmt.Sprintf(`{"http":false,"coraza_all":%v,"coraza_rule_ids":[]}`, excluded)}}
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
			require.True(t, events[0].RuleMsg == "[REDACTED]", "message was not masked before truncation")
			require.True(t, events[0].MatchData == "[REDACTED]", "match data was not masked before truncation")
			require.Equal(t, "independent finding", events[1].RuleMsg)
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

func TestManagedHeaderPrivacyMarkerCollisionAndCaptureBudgets(t *testing.T) {
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
		pairs[i] = managedHeaderCredential{Name: "X-Key", Value: fmt.Sprintf("key-%d!", i)}
	}
	r := privacyRequest(t, pairs, http.Header{"X-Key": {strings.Repeat("x", managedHeaderWorkMaxBytes+1)}})
	bridge := &CorazaPrivacyBridge{}
	release := bridge.Bind("privacy-work-overflow", r)
	defer release()
	require.True(t, bridge.Redact("privacy-work-overflow", "unrelated text") == "", "privacy fallback retained text")
}

func TestManagedHeaderPrivacyRegistryHardBoundsAndCleanup(t *testing.T) {
	registry := newManagedHeaderRegistry(2, 2, 8)
	bridge := &CorazaPrivacyBridge{registry: registry}
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "abcd"}}, http.Header{"X-Key": {"abcd"}})
	releases := []func(){bridge.Bind("bound-a", r), bridge.Bind("bound-b", r), bridge.Bind("bound-c", r)}
	require.True(t, bridge.Redact("bound-a", "abcd") == "[REDACTED]", "managed text was not masked")
	require.True(t, bridge.Redact("bound-c", "abcd") == "", "privacy fallback retained text")
	require.Len(t, registry.entries, 2)
	require.Equal(t, 2, registry.slots)
	require.Equal(t, 8, registry.bytes)
	for _, release := range releases {
		release()
		release()
	}
	require.Len(t, registry.entries, 0)
	require.Zero(t, registry.slots)
	require.Zero(t, registry.bytes)
	release := bridge.Bind("bound-new", r)
	require.True(t, bridge.Redact("bound-new", "abcd") == "[REDACTED]", "managed text was not masked")
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
			if bridge.Redact(id, "race-key!") != "[REDACTED]" {
				t.Error("credential was not masked")
			}
		}(i)
	}
	wg.Wait()
}

func TestManagedHeaderPrivacyRedactionBudgetSharedAcrossWAFTransactions(t *testing.T) {
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "budget-key!"}}, http.Header{"X-Key": {"budget-key!"}})
	bridge := &CorazaPrivacyBridge{}
	a := bridge.Bind("budget-a", r)
	defer a()
	b := bridge.Bind("budget-b", r)
	defer b()
	text := strings.Repeat("x", managedHeaderWorkMaxBytes/2)
	require.NotEmpty(t, bridge.Redact("budget-a", text))
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
