package apxstats

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

// The Coraza writer's pointer across a cluster's life, with no fold table. This
// file runs unchanged on the commit before fold_hosts, so it pins that nothing here
// moved for a cluster with no table.
func TestCorazaWriterPublishLifecycle(t *testing.T) {
	ingest, _ := captureServer(t, http.StatusOK)
	t.Cleanup(ingest.Close)
	t.Cleanup(func() { _ = caddy.Stop() })

	config := func(addr string, extra ...any) []byte {
		routes := append([]any{}, extra...)
		routes = append(routes, map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 200, "body": "ok"}}})
		raw, err := json.Marshal(map[string]any{
			"admin": map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
			"apps": map[string]any{
				"apx_stats": map[string]any{"proxy_server_id": 89, "hash_salt": "salt",
					"ingest": map[string]any{"url": ingest.URL, "auth_token": "t", "flush_interval_ms": 50}},
				"http": map[string]any{"grace_period": "1s", "servers": map[string]any{"edge": map[string]any{
					"listen": []string{addr}, "automatic_https": map[string]any{"disable": true},
					"routes": []any{map[string]any{"handle": []any{
						map[string]any{"handler": "apx_stats"},
						map[string]any{"handler": "subroute", "routes": routes},
					}}},
				}}},
			},
		})
		require.NoError(t, err)
		return raw
	}
	serves := func(addr string) {
		t.Helper()
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get("http://" + addr + "/")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, 200, resp.StatusCode)
	}

	// Cold start: published and started.
	addr := freeLoopbackAddr(t)
	require.NoError(t, caddy.Load(config(addr), true))
	first := corazaApp.Load()
	require.NotNil(t, first)
	require.True(t, first.started.Load())
	serves(addr)

	// Reload: the replacement takes over.
	second := freeLoopbackAddr(t)
	require.NoError(t, caddy.Load(config(second), true))
	live := corazaApp.Load()
	require.NotSame(t, first, live)
	require.True(t, live.started.Load())
	serves(second)

	// Refused at provision: the rejected app stays published and never starts.
	bad := map[string]any{"handle": []any{map[string]any{"handler": "apx_no_such_handler"}}}
	require.Error(t, caddy.Load(config(freeLoopbackAddr(t), bad), true))
	rejected := corazaApp.Load()
	require.NotSame(t, live, rejected)
	require.NotNil(t, rejected)
	require.False(t, rejected.started.Load())
	serves(second)

	// Refused at Start, on an occupied listener. Caddy starts apps in map order, so
	// the replacement either never started and stays published, or started, stopped
	// and cleared the pointer. Either way the live app isn't republished.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()
	require.Error(t, caddy.Load(config(occupied.Addr().String()), true))
	require.NotSame(t, live, corazaApp.Load())
	serves(second)

	// The next good load publishes again.
	third := freeLoopbackAddr(t)
	require.NoError(t, caddy.Load(config(third), true))
	final := corazaApp.Load()
	require.NotNil(t, final)
	require.True(t, final.started.Load())
	serves(third)

	// Stop clears the pointer.
	require.NoError(t, caddy.Stop())
	require.Nil(t, corazaApp.Load())
}
