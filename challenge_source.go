package apxstats

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// challengeSourceVarKey is the request var the apx_challenge handler sets
// beside every outcome: who asked for the challenge.
const challengeSourceVarKey = "apx_challenge_source"

// challengeSources is the closed set of values a challenge_attempt row may
// carry in `source`. The Phoenix ingest folds anything else to "unknown", and
// its fixture (apx_caddy_stats_challenge_sources.txt) must equal this list.
// "" is not in the set: it means the var was absent (an older challenge
// plugin) and is written as "".
var challengeSources = []string{"automatic", "staff", "customer", "edge_sequence", "reputation", "unknown"}

// readChallengeSource reads the `apx_challenge_source` request var. It returns
// the matching package-level constant, so storing it in a key needs no clone
// and no allocation, "" when the var is absent, and "unknown" for any other
// value (including a non-string).
func readChallengeSource(r *http.Request) string {
	v := caddyhttp.GetVar(r.Context(), challengeSourceVarKey)
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return "unknown"
	}
	if s == "" {
		return ""
	}
	for _, known := range challengeSources {
		if s == known {
			return known
		}
	}
	return "unknown"
}
