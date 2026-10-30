package apxstats

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

type fakeDomainHealthApp struct {
	fakeApp
	health []struct {
		key     domainHealthKey
		counter domainHealthCounter
	}
}

func (a *fakeDomainHealthApp) RecordDomainHealth(key domainHealthKey, counter domainHealthCounter) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.health = append(a.health, struct {
		key     domainHealthKey
		counter domainHealthCounter
	}{key, counter})
}

func TestDomainHealthHandlerReadsServerVariableAfterRoute(t *testing.T) {
	app := &fakeDomainHealthApp{}
	handler := &StatsHandler{app: app}
	r := newRequestWithReplacer("GET", "https://site.example/page", "12", upstreamSelected("origin.example:443"))
	r.Header.Set("apx-domain-health-key", strings.Repeat("b", 64))
	before := timeNowUnixMin()
	err := handler.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		caddyhttp.SetVar(r.Context(), domainHealthVar, strings.Repeat("a", 64))
		w.WriteHeader(200)
		return nil
	}))
	require.NoError(t, err)
	require.Len(t, app.health, 1)
	require.Equal(t, strings.Repeat("a", 64), app.health[0].key.ConfigurationKey)
	require.Equal(t, uint32(12), app.health[0].key.VhostID)
	require.GreaterOrEqual(t, app.health[0].key.TsUnixMin, before)
	require.LessOrEqual(t, app.health[0].key.TsUnixMin, timeNowUnixMin())
	require.Equal(t, domainHealthCounter{RequestCount: 1, RoutingResponses: 1, UpstreamResponses: 1, UpstreamSuccesses: 1}, app.health[0].counter)
}

func TestDomainHealthHandlerRefusesMissingOrUntrustedIdentity(t *testing.T) {
	for _, tc := range []struct{ name, vhost, key string }{
		{"no fingerprint", "12", ""},
		{"uppercase fingerprint", "12", strings.Repeat("A", 64)},
		{"short fingerprint", "12", "abc"},
		{"invalid fingerprint", "12", strings.Repeat("g", 64)},
		{"no matched vhost", "", strings.Repeat("a", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &fakeDomainHealthApp{}
			r := newRequestWithReplacer("GET", "https://site.example/", tc.vhost, map[string]any{"http.vars.apx_domain_health_key": strings.Repeat("c", 64)})
			r.Header.Set("apx-domain-health-key", strings.Repeat("c", 64))
			if tc.key != "" {
				caddyhttp.SetVar(r.Context(), domainHealthVar, tc.key)
			}
			require.NoError(t, (&StatsHandler{app: app}).ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error { w.WriteHeader(200); return nil })))
			require.Empty(t, app.health)
		})
	}
}

func TestDomainHealthHandlerSkipsMonitorAndHolderOnly(t *testing.T) {
	for _, tc := range []struct {
		name            string
		holder, monitor bool
	}{
		{"monitor", false, true}, {"holder", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &fakeDomainHealthApp{}
			r := newRequestWithReplacer("GET", "https://site.example/", "12", upstreamSelected("origin:443"))
			caddyhttp.SetVar(r.Context(), domainHealthVar, strings.Repeat("a", 64))
			if tc.monitor {
				r.Header.Set("apx-monitor", "true")
			}
			require.NoError(t, (&StatsHandler{app: app, HolderOnly: tc.holder}).ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error { w.WriteHeader(200); return nil })))
			require.Empty(t, app.health)
		})
	}
}

func TestDomainHealthOriginClasses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		repl   map[string]any
		err    error
		want   domainHealthCounter
	}{
		{"success", 204, upstreamSelected("origin:443"), nil, domainHealthCounter{1, 1, 1, 1, 0, 0}},
		{"redirect upstream", 302, upstreamSelected("origin:443"), nil, domainHealthCounter{1, 1, 1, 1, 0, 0}},
		{"auth reachable", 401, upstreamSelected("origin:443"), nil, domainHealthCounter{1, 1, 1, 0, 0, 0}},
		{"upstream error", 503, upstreamSelected("origin:443"), nil, domainHealthCounter{1, 1, 1, 0, 1, 0}},
		{"edge redirect", 301, nil, nil, domainHealthCounter{1, 1, 0, 0, 0, 0}},
		{"edge block", 403, map[string]any{"http.vars.apx_block_reason": "waf"}, nil, domainHealthCounter{1, 1, 0, 0, 0, 0}},
		{"proxy failure", 0, upstreamSelected("origin:443"), caddyhttp.Error(502, fmt.Errorf("dial failed")), domainHealthCounter{1, 0, 0, 0, 0, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &fakeDomainHealthApp{}
			r := newRequestWithReplacer("GET", "https://site.example/", "12", tc.repl)
			caddyhttp.SetVar(r.Context(), domainHealthVar, strings.Repeat("a", 64))
			_ = (&StatsHandler{app: app}).ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				return tc.err
			}))
			require.Len(t, app.health, 1)
			require.Equal(t, tc.want, app.health[0].counter)
		})
	}
}

func TestDomainHealthDrainPreservesGenerationAndSourceMinute(t *testing.T) {
	app := newTestApp(t, "http://not-used.invalid", "k")
	minute := uint32(29_800_000)
	for _, key := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		app.RecordDomainHealth(domainHealthKey{minute, 12, key}, domainHealthCounter{RequestCount: 2, RoutingResponses: 2, UpstreamResponses: 2, UpstreamSuccesses: 1, Upstream5xx: 1})
	}
	body, rows, ok := app.drainAndEncode(true)
	require.True(t, ok, "health-only retired HTTP drain must ship")
	require.Equal(t, 2, rows)
	gz, err := gzip.NewReader(strings.NewReader(string(body)))
	require.NoError(t, err)
	defer gz.Close()
	decoder := json.NewDecoder(gz)
	keys := map[string]bool{}
	for {
		var row map[string]any
		err := decoder.Decode(&row)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		require.Equal(t, "domain_health", row["_type"])
		require.Equal(t, formatTs(minute), row["ts"], "delivery time cannot restamp observation")
		require.Equal(t, float64(42), row["proxy_server_id"])
		require.Equal(t, float64(12), row["vhost_id"])
		require.Equal(t, float64(2), row["request_count"])
		require.Equal(t, float64(2), row["routing_responses"])
		require.Equal(t, float64(2), row["upstream_responses"])
		require.Equal(t, float64(1), row["upstream_successes"])
		require.Equal(t, float64(1), row["upstream_5xx"])
		require.Equal(t, float64(0), row["proxy_errors"])
		keys[row["configuration_key"].(string)] = true
	}
	require.Len(t, keys, 2)
	require.Zero(t, app.domainHealthKeys.Load())
	require.Zero(t, app.memGov.bufferBytes.Load())
	_, _, ok = app.drainAndEncode(false)
	require.False(t, ok)
}

func TestDomainHealthPiggybacksExistingIngestPost(t *testing.T) {
	server, captured := captureServer(t, http.StatusNoContent)
	defer server.Close()
	app := newTestApp(t, server.URL, "k")
	r := newRequestWithReplacer("GET", "https://site.example/", "12", upstreamSelected("origin:443"))
	caddyhttp.SetVar(r.Context(), domainHealthVar, strings.Repeat("a", 64))
	require.NoError(t, (&StatsHandler{app: app}).ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(200)
		return nil
	})))
	app.flushOnce(0)
	posts := captured()
	require.Len(t, posts, 1, "health evidence must not create its own network request")
	require.Len(t, posts[0].rows, 2)
	var health, counter map[string]any
	for _, row := range posts[0].rows {
		if row["_type"] == "domain_health" {
			health = row
		} else {
			counter = row
		}
	}
	require.NotNil(t, health)
	require.NotNil(t, counter)
	require.Equal(t, strings.Repeat("a", 64), health["configuration_key"])
	require.NotContains(t, counter, "configuration_key", "normal request-counter cardinality must remain unchanged")
}

func TestDomainHealthKeyAndMemoryCaps(t *testing.T) {
	t.Run("cardinality", func(t *testing.T) {
		app := newTestApp(t, "http://not-used.invalid", "k", func(a *StatsApp) { a.Ingest.MaxBufferRows = 2 })
		key := domainHealthKey{1, 12, strings.Repeat("a", 64)}
		app.RecordDomainHealth(key, domainHealthCounter{RequestCount: 1})
		app.RecordDomainHealth(domainHealthKey{1, 13, key.ConfigurationKey}, domainHealthCounter{RequestCount: 1})
		app.RecordDomainHealth(domainHealthKey{1, 14, key.ConfigurationKey}, domainHealthCounter{RequestCount: 1})
		app.RecordDomainHealth(key, domainHealthCounter{RequestCount: 1})
		snapshot := app.drainDomainHealth()
		require.Len(t, snapshot, 2)
		require.Equal(t, uint64(2), snapshot[key].RequestCount, "existing admitted keys remain unsampled")
		require.Zero(t, app.memGov.bufferBytes.Load())
		app.RecordDomainHealth(domainHealthKey{2, 14, key.ConfigurationKey}, domainHealthCounter{RequestCount: 1})
		require.Len(t, app.drainDomainHealth(), 1, "drain releases retired keys and slots")
	})
	t.Run("memory", func(t *testing.T) {
		app := newTestApp(t, "http://not-used.invalid", "k")
		app.memGov.shareBudget = domainHealthEntryBytes - 1
		app.RecordDomainHealth(domainHealthKey{1, 12, strings.Repeat("a", 64)}, domainHealthCounter{RequestCount: 1})
		require.Empty(t, app.drainDomainHealth())
		require.Zero(t, app.domainHealthKeys.Load())
		require.Zero(t, app.memGov.bufferBytes.Load())
	})
}

func TestDomainHealthConcurrentRecordsAndDrains(t *testing.T) {
	app := newTestApp(t, "http://not-used.invalid", "k")
	const writers, perWriter = 40, 250
	key := strings.Repeat("a", 64)
	var writersDone sync.WaitGroup
	writersDone.Add(writers)
	for i := 0; i < writers; i++ {
		go func(vhost uint32) {
			defer writersDone.Done()
			for j := 0; j < perWriter; j++ {
				app.RecordDomainHealth(domainHealthKey{1, vhost, key}, domainHealthCounter{RequestCount: 1, RoutingResponses: 1, UpstreamResponses: 1})
			}
		}(uint32(i%10 + 1))
	}
	ctx, cancel := context.WithCancel(context.Background())
	drained := make(chan uint64)
	go func() {
		var count uint64
		for ctx.Err() == nil {
			for _, counter := range app.drainDomainHealth() {
				count += counter.RequestCount
			}
			time.Sleep(time.Microsecond)
		}
		for _, counter := range app.drainDomainHealth() {
			count += counter.RequestCount
		}
		drained <- count
	}()
	writersDone.Wait()
	cancel()
	require.Equal(t, uint64(writers*perWriter), <-drained)
	require.Zero(t, app.domainHealthKeys.Load())
	require.Zero(t, app.memGov.bufferBytes.Load())
}

func BenchmarkDomainHealthRecord(b *testing.B) {
	app := &StatsApp{cfg: ingestRuntime{maxBuffer: 1_000}}
	for i := range app.shards {
		app.shards[i] = &counterShard{}
	}
	key := domainHealthKey{1, 12, strings.Repeat("a", 64)}
	delta := domainHealthCounter{RequestCount: 1, RoutingResponses: 1, UpstreamResponses: 1}
	app.RecordDomainHealth(key, delta)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			app.RecordDomainHealth(key, delta)
		}
	})
}
