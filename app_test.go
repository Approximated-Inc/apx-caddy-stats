package apxchallenge

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

func TestAppProvisionReadsSecretFromEnv(t *testing.T) {
	t.Setenv("APX_CHALLENGE_SECRET", "test-secret-123")
	app := &ChallengeApp{DifficultyCfg: 16, SecretEnvVar: "APX_CHALLENGE_SECRET", VerifyPathCfg: "/__apx_challenge/verify"}
	require.NoError(t, app.Provision(caddy.Context{}))
	require.Equal(t, "test-secret-123", app.Secret())
	require.Equal(t, 16, app.Difficulty())
	require.Equal(t, "/__apx_challenge/verify", app.VerifyPath())
}

func TestAppProvisionDefaults(t *testing.T) {
	t.Setenv("APX_CHALLENGE_SECRET", "s")
	app := &ChallengeApp{}
	require.NoError(t, app.Provision(caddy.Context{}))
	require.Equal(t, 16, app.Difficulty())
	require.Equal(t, "/__apx_challenge/verify", app.VerifyPath())
	require.Equal(t, "s", app.Secret())
}

func TestAppProvisionErrorsWhenSecretEmpty(t *testing.T) {
	t.Setenv("APX_CHALLENGE_SECRET", "")
	app := &ChallengeApp{}
	require.Error(t, app.Provision(caddy.Context{}))
}

func TestAppModuleID(t *testing.T) {
	require.Equal(t, "apx_challenge", string((&ChallengeApp{}).CaddyModule().ID))
}
