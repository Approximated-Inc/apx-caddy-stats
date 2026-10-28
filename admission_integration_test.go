package apxstats

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

// C8: the full JSON shape Phoenix emits, through caddy.Load. With the node
// at level 2 and requests held in flight, a static asset gets a fast 503,
// an HTML navigation is served, and the stats handler records no counter
// row for the shed request (it never reached the vhost route's vars).
func TestAdmissionThroughCaddyLoad(t *testing.T) {
	resetOverload(t)
	origSig, origInterval := overload.signals, overloadSampleInterval
	overload.signals, overloadSampleInterval = &fakeSignals{}, 5*time.Millisecond
	t.Cleanup(func() { overload.signals, overloadSampleInterval = origSig, origInterval })

	ingest, posts := captureServer(t, http.StatusOK)
	t.Cleanup(ingest.Close)
	release := make(chan struct{})
	var releaseOnce sync.Once
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); slow.Close() })

	addr := freeLoopbackAddr(t)
	vhost := func(id string, handlers ...any) []any {
		return append([]any{map[string]any{"handler": "vars", "vhost_id": id}}, handlers...)
	}
	raw, err := json.Marshal(map[string]any{
		"admin":   map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"storage": map[string]any{"module": "file_system", "root": t.TempDir()},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"apx_stats": map[string]any{
				"proxy_server_id": 89,
				"overload":        map[string]any{"waf": "observe", "admission": map[string]any{"mode": "enforce"}},
				"ingest": map[string]any{
					"url":               ingest.URL,
					"auth_token":        "test-token",
					"flush_interval_ms": 100,
				},
			},
			"http": map[string]any{
				"grace_period": "1s",
				"servers": map[string]any{"edge": map[string]any{
					"listen":          []string{addr},
					"automatic_https": map[string]any{"disable": true},
					"routes": []any{map[string]any{"handle": []any{
						map[string]any{"handler": "apx_stats"},
						map[string]any{"handler": "apx_admission"},
						map[string]any{"handler": "subroute", "routes": []any{
							map[string]any{
								"match":  []any{map[string]any{"path": []string{"/slow"}}},
								"handle": vhost("201", map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": slow.Listener.Addr().String()}}}),
							},
							map[string]any{"handle": vhost("101", map[string]any{"handler": "static_response", "status_code": 200})},
						}},
					}}},
				}},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, caddy.Load(raw, true))
	t.Cleanup(func() { _ = caddy.Stop() })
	require.Eventually(t, func() bool { return overload.Level() == 2 && admissionLimitNow.Load() == 8 }, 2*time.Second, 5*time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}
	var held sync.WaitGroup
	for i := 0; i < 5; i++ {
		held.Add(1)
		go func() {
			defer held.Done()
			if resp, err := client.Get("http://" + addr + "/slow"); err == nil {
				_ = resp.Body.Close()
			}
		}()
	}
	require.Eventually(t, func() bool { return admissionInflight.Load() == 5 }, 2*time.Second, 5*time.Millisecond)

	get := func(path string, headers ...string) *http.Response {
		req, err := http.NewRequest("GET", "http://"+addr+path, nil)
		require.NoError(t, err)
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		start := time.Now()
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Less(t, time.Since(start), time.Second)
		return resp
	}
	static := get("/app.js")
	require.Equal(t, http.StatusServiceUnavailable, static.StatusCode)
	require.Equal(t, "1", static.Header.Get("Apx-Overload"))
	require.Equal(t, http.StatusOK, get("/", "Accept", "text/html").StatusCode)

	releaseOnce.Do(func() { close(release) })
	held.Wait()
	var counters []map[string]any
	require.Eventually(t, func() bool {
		counters = counters[:0]
		for _, p := range posts() {
			for _, row := range p.rows {
				if row["request_count"] != nil {
					counters = append(counters, row)
				}
			}
		}
		return len(counters) > 0
	}, 3*time.Second, 20*time.Millisecond)
	for _, row := range counters {
		require.NotEqual(t, float64(503), row["status"], "a shed request records no counter row")
	}
	require.EqualValues(t, 1, overloadCounts.shed[admitP3].Load())
}
