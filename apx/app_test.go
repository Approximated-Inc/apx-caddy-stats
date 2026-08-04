package apxapp

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/stretchr/testify/require"
)

func TestAppProvisionDefaults(t *testing.T) {
	var a App
	require.NoError(t, json.Unmarshal([]byte(`{}`), &a))
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	require.NoError(t, a.Provision(ctx))
	require.False(t, a.Puller.Enabled)
	require.Equal(t, 60, a.Puller.IntervalSeconds)
	require.NoError(t, a.Start())
	require.False(t, a.PullerRunning()) // disabled by default
	require.NoError(t, a.Stop())
}

func TestSharedStateSurvivesReload(t *testing.T) {
	// two apps provisioned sequentially (simulating config reload) see the same SharedState
	s1, err := loadSharedState()
	require.NoError(t, err)
	s1.SetLastStamp("123")
	s2, err := loadSharedState()
	require.NoError(t, err)
	require.Equal(t, "123", s2.LastStamp())
}

func TestCaddytestLoadsApp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping caddytest integration test in -short mode (binds localhost ports)")
	}
	caddytest.Default.AdminPort = 2999
	tester := caddytest.NewTester(t)
	tester.InitServer(`{ "admin": {"listen": "localhost:2999"}, "apps": {"apx": {"puller": {"enabled": false}}} }`, "json")
}
