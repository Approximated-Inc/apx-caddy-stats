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
	require.Equal(t, "[REDACTED]", bridge.Redact("privacy-original", "matched="+secret))
	require.Equal(t, "ordinary", bridge.Redact("privacy-original", "ordinary"))
	require.Nil(t, requestDefenseHolder(r).snapshot, "privacy must not publish evidence authority")
	require.NotContains(t, fmt.Sprint(r.Header), secret)
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
		require.Empty(t, bridge.Redact(id, "a-key! b-key!"))
		if firstCloses {
			a()
		} else {
			b()
		}
		require.Empty(t, bridge.Redact(id, "a-key! b-key!"))
		third := bridge.Bind(id, privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "c-key!"}}, http.Header{"X-Key": {"c-key!"}}))
		require.Empty(t, bridge.Redact(id, "a-key! b-key! c-key!"))
		a()
		b()
		require.Empty(t, bridge.Redact(id, "a-key! b-key! c-key!"))
		third()
		require.Empty(t, bridge.Redact(id, "a-key! b-key!"))
	}
}

func TestManagedHeaderPrivacyMarkerCollisionAndCaptureBudgets(t *testing.T) {
	for _, value := range []string{"REDACTED", "[REDACTED]", "writer-key!"} {
		r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: value}}, http.Header{"X-Key": {value}})
		bridge := &CorazaPrivacyBridge{}
		id := "privacy-marker-" + value
		release := bridge.Bind(id, r)
		masked := bridge.Redact(id, "matched="+value)
		require.NotContains(t, masked, value)
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
	require.Empty(t, bridge.Redact("privacy-work-overflow", "unrelated text"))
}

func TestManagedHeaderPrivacyRegistryHardBoundsAndCleanup(t *testing.T) {
	registry := newManagedHeaderRegistry(2, 2, 8)
	bridge := &CorazaPrivacyBridge{registry: registry}
	r := privacyRequest(t, []managedHeaderCredential{{Name: "X-Key", Value: "abcd"}}, http.Header{"X-Key": {"abcd"}})
	releases := []func(){bridge.Bind("bound-a", r), bridge.Bind("bound-b", r), bridge.Bind("bound-c", r)}
	require.Equal(t, "[REDACTED]", bridge.Redact("bound-a", "abcd"))
	require.Empty(t, bridge.Redact("bound-c", "abcd"))
	require.Len(t, registry.entries, 2)
	require.Equal(t, 2, registry.slots)
	require.Equal(t, 8, registry.bytes)
	for _, release := range releases {
		release()
		release()
	}
	require.Empty(t, registry.entries)
	require.Zero(t, registry.slots)
	require.Zero(t, registry.bytes)
	release := bridge.Bind("bound-new", r)
	require.Equal(t, "[REDACTED]", bridge.Redact("bound-new", "abcd"))
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
	require.Empty(t, bridge.Redact("budget-b", text))
	require.Empty(t, bridge.Redact("budget-a", "small ordinary field"))
}
