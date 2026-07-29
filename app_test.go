package apxchallenge

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

func TestAppProvisionReadsSecretFromConfig(t *testing.T) {
	app := &ChallengeApp{DifficultyCfg: 16, SecretCfg: "test-secret-123", VerifyPathCfg: "/__apx_challenge/verify"}
	require.NoError(t, app.Provision(caddy.Context{}))
	require.Equal(t, "test-secret-123", app.Secret())
	require.Equal(t, 16, app.Difficulty())
	require.Equal(t, "/__apx_challenge/verify", app.VerifyPath())
}

func TestAppProvisionDefaults(t *testing.T) {
	app := &ChallengeApp{SecretCfg: "s"}
	require.NoError(t, app.Provision(caddy.Context{}))
	require.Equal(t, 16, app.Difficulty())
	require.Equal(t, "/__apx_challenge/verify", app.VerifyPath())
	require.Equal(t, "s", app.Secret())
}

func TestAppProvisionErrorsWhenSecretEmpty(t *testing.T) {
	app := &ChallengeApp{}
	require.Error(t, app.Provision(caddy.Context{}))
}

func TestAppModuleID(t *testing.T) {
	require.Equal(t, "apx_challenge", string((&ChallengeApp{}).CaddyModule().ID))
}

func TestFormDefaultsApplied(t *testing.T) {
	a := &ChallengeApp{SecretCfg: "s"}
	if err := a.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if a.FormDifficulty() != 14 || a.FormScoring() != "lenient" || a.FormBodyCap() != 1048576 {
		t.Fatalf("defaults wrong: diff=%d scoring=%q cap=%d", a.FormDifficulty(), a.FormScoring(), a.FormBodyCap())
	}
	if a.FormTokenTTL() != 600*time.Second || a.FormMinFillMs() != 800 {
		t.Fatalf("ttl/fill wrong: ttl=%v fill=%d", a.FormTokenTTL(), a.FormMinFillMs())
	}
}
