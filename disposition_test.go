package apxstats

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveDisposition(t *testing.T) {
	cases := []struct {
		name    string
		reason  string
		outcome string
		want    string
	}{
		{"served_no_signals", "", "", dispServed},
		{"waf_block", "waf", "", dispWafBlocked},
		{"rate_limit_block", "rate_limit", "", dispRateLimited},
		{"challenge_issued", "", "issued", dispChallengeIssued},
		{"challenge_passed", "", "passed", dispChallengePassed},
		{"challenge_failed", "", "failed", dispChallengeFailed},
		{"challenge_passed_prior", "", "passed_recently", dispChallengePassedPrior},
		// Block reasons take precedence over challenge outcomes.
		{"waf_beats_challenge", "waf", "passed", dispWafBlocked},
		{"rate_limit_beats_challenge", "rate_limit", "issued", dispRateLimited},
		// Unknown challenge outcome (defensive) falls through to served.
		{"unknown_outcome_is_served", "", "bogus", dispServed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, deriveDisposition(c.reason, c.outcome))
		})
	}
}

func TestDeriveDisposition_ExactWireStrings(t *testing.T) {
	// The seven disposition tokens are a Phoenix wire contract — pin them.
	require.Equal(t, "served", dispServed)
	require.Equal(t, "waf_blocked", dispWafBlocked)
	require.Equal(t, "rate_limited", dispRateLimited)
	require.Equal(t, "challenge_issued", dispChallengeIssued)
	require.Equal(t, "challenge_passed", dispChallengePassed)
	require.Equal(t, "challenge_failed", dispChallengeFailed)
	require.Equal(t, "challenge_passed_prior", dispChallengePassedPrior)
}
