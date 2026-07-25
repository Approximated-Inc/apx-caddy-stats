package apxstats

// The seven request_event dispositions. Exactly one is stamped per row.
// These strings are part of the Phoenix wire contract (the `disposition`
// field on `_type:"request_event"`). Block reasons take precedence over
// challenge outcomes; anything else is served.
const (
	dispServed               = "served"
	dispWafBlocked           = "waf_blocked"
	dispRateLimited          = "rate_limited"
	dispChallengeIssued      = "challenge_issued"
	dispChallengePassed      = "challenge_passed"
	dispChallengeFailed      = "challenge_failed"
	dispChallengePassedPrior = "challenge_passed_prior"
)

// deriveDisposition maps the block-reason (from blockReason: "waf" |
// "rate_limit" | "") and the challenge outcome var (from
// readChallengeOutcome: "issued" | "passed" | "passed_recently" | "failed"
// | "") to exactly one disposition. Block reasons win over challenge
// outcomes; an empty/unknown pair is "served".
func deriveDisposition(blockReason, challengeOutcome string) string {
	switch blockReason {
	case "waf":
		return dispWafBlocked
	case "rate_limit":
		return dispRateLimited
	}
	switch challengeOutcome {
	case "issued":
		return dispChallengeIssued
	case "passed":
		return dispChallengePassed
	case "failed":
		return dispChallengeFailed
	case "passed_recently":
		return dispChallengePassedPrior
	}
	return dispServed
}
