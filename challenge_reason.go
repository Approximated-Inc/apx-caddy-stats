package apxstats

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// challengeReasonOutcomes composes the apx_challenge handler's bare outcome
// and the reason it sets beside it (`apx_challenge_reason`) into the outcome
// stored on a challenge_attempt row. Only these pairs compose; any other
// reason, or none (an older challenge plugin), keeps the bare outcome, so the
// stored set stays closed and an older plugin records exactly what it did.
// The Phoenix ingest whitelist (`Approximated.Analytics.ChallengeOutcomes`)
// must accept every value here before an image carrying it rolls out.
//
// The request_event disposition still reads the bare outcome.
var challengeReasonOutcomes = map[[2]string]string{
	{"issued", "document"}:       "issued_document",
	{"issued", "other"}:          "issued_other",
	{"failed", "api"}:            "not_shown_api",
	{"failed", "stream"}:         "not_shown_stream",
	{"failed", "token"}:          "failed_token",
	{"failed", "expired"}:        "failed_expired",
	{"failed", "binding"}:        "failed_binding",
	{"failed", "proof"}:          "failed_proof",
	{"failed", "replay"}:         "failed_replay",
	{"failed", "render"}:         "failed_render",
	{"failed", "fallback_limit"}: "failed_fallback_limit",
}

// challengeAttemptOutcome is the stored outcome for a bare outcome and reason.
func challengeAttemptOutcome(outcome, reason string) string {
	if reason == "" {
		return outcome
	}
	if composed, ok := challengeReasonOutcomes[[2]string{outcome, reason}]; ok {
		return composed
	}
	return outcome
}

// readChallengeReason reads the `apx_challenge_reason` request var the
// apx_challenge handler sets beside an issued or failed outcome, or "".
// Visible here for the same reason as readChallengeOutcome.
func readChallengeReason(r *http.Request) string {
	s, _ := caddyhttp.GetVar(r.Context(), "apx_challenge_reason").(string)
	return s
}
