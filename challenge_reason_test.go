package apxstats

import (
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

func TestChallengeAttemptOutcomeComposesKnownPairs(t *testing.T) {
	cases := []struct{ outcome, reason, want string }{
		{"issued", "document", "issued_document"},
		{"issued", "other", "issued_other"},
		{"failed", "api", "not_shown_api"},
		{"failed", "stream", "not_shown_stream"},
		{"failed", "token", "failed_token"},
		{"failed", "expired", "failed_expired"},
		{"failed", "binding", "failed_binding"},
		{"failed", "proof", "failed_proof"},
		{"failed", "stale_difficulty", "failed_stale_difficulty"},
		{"failed", "replay", "failed_replay"},
		{"failed", "render_cookie", "failed_render_cookie"},
		{"failed", "render_pixel", "failed_render_pixel"},
		{"failed", "render_dwell", "failed_render_dwell"},
		{"failed", "fallback_replay", "failed_fallback_replay"},
		{"failed", "fallback_limit", "failed_fallback_limit"},
		{"passed_recently", "fallback", "passed_recently_fallback"},
		// No reason (an older challenge plugin): the bare outcome, as before.
		{"issued", "", "issued"},
		{"failed", "", "failed"},
		{"passed", "", "passed"},
		{"passed_fallback", "", "passed_fallback"},
		{"passed_recently", "", "passed_recently"},
		// Unknown pairs keep the bare outcome, so the stored set stays closed.
		{"failed", "something_new", "failed"},
		{"issued", "proof", "issued"},
		{"passed", "document", "passed"},
		{"failed", "render", "failed"},
		{"passed", "fallback", "passed"},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, challengeAttemptOutcome(tc.outcome, tc.reason), "%s + %q", tc.outcome, tc.reason)
	}
	require.Len(t, challengeReasonOutcomes, 16)
}

func TestServeHTTP_ChallengeReasonComposesStoredOutcomeOnly(t *testing.T) {
	// The challenge_attempt row carries the composed outcome; the request_event
	// disposition still comes from the bare outcome.
	app := &fakeApp{modeV2: true}
	h := &StatsHandler{app: app}

	r := newRequestWithChallengeOutcome("POST", "/api", "example.com", "failed")
	caddyhttp.SetVar(r.Context(), "apx_challenge_reason", "api")
	r.RemoteAddr = "203.0.113.7:54321"
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, nextHandler(429)))

	ch := app.challengeSnapshot()
	require.Len(t, ch, 1)
	require.Equal(t, "not_shown_api", ch[0].outcome)
	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, dispChallengeFailed, evs[0].Disposition)

	r = newRequestWithChallengeOutcome("GET", "/", "example.com", "issued")
	caddyhttp.SetVar(r.Context(), "apx_challenge_reason", "document")
	r.RemoteAddr = "203.0.113.8:54321"
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, nextHandler(200)))
	ch = app.challengeSnapshot()
	require.Len(t, ch, 2)
	require.Equal(t, "issued_document", ch[1].outcome)
	evs = app.reqEventSnapshot()
	require.Equal(t, dispChallengeIssued, evs[1].Disposition)
}

func TestServeHTTP_NoChallengeReasonKeepsBareOutcome(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app}
	r := newRequestWithChallengeOutcome("GET", "/", "example.com", "failed")
	r.RemoteAddr = "203.0.113.7:54321"
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, nextHandler(429)))
	ch := app.challengeSnapshot()
	require.Len(t, ch, 1)
	require.Equal(t, "failed", ch[0].outcome)
}

func TestServeHTTP_FallbackCookiePassKeepsPriorDisposition(t *testing.T) {
	app := &fakeApp{modeV2: true}
	h := &StatsHandler{app: app}
	r := newRequestWithChallengeOutcome("GET", "/", "example.com", "passed_recently")
	caddyhttp.SetVar(r.Context(), "apx_challenge_reason", "fallback")
	r.RemoteAddr = "203.0.113.7:54321"
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, nextHandler(200)))

	ch := app.challengeSnapshot()
	require.Len(t, ch, 1)
	require.Equal(t, "passed_recently_fallback", ch[0].outcome)
	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, dispChallengePassedPrior, evs[0].Disposition)
}
