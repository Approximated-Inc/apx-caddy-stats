package apxstats

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/v2/modules/logging"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestLookupFoldHost(t *testing.T) {
	table := map[string]uint32{"a.fold.test": 42, "zz.fold.test": 45, "xn--bcher-kva.fold.test": 43, "under_score.test": 44}
	long := strings.Repeat("a", 254)
	for raw, want := range map[string]uint32{
		"a.fold.test":       42,
		"A.FOLD.TEST":       42,
		"a.Fold.Test":       42,
		"a.fold.test.":      42,
		"A.FOLD.TEST.":      42,
		"a.fold.test:443":   42,
		"a.fold.test.:8443": 42,
		"a.fold.test:":      42,
		// Caddy's host matcher strips any port, so these reach the same routes.
		"a.fold.test:999999999":   42,
		"ZZ.FOLD.TEST":            45,
		"xn--bcher-kva.fold.test": 43,
		"XN--BCHER-KVA.FOLD.TEST": 43,
		"under_score.test":        44,
		"a.fold.test..":           0,
		"a.fold.test:http":        0,
		"a.fold.test:80:80":       0,
		"[::1]:443":               0,
		"[::1]":                   0,
		"::1":                     0,
		"b.fold.test":             0,
		"fold.test":               0,
		"bücher.fold.test":        0,
		"":                        0,
		":443":                    0,
		".":                       0,
		long:                      0,
	} {
		id, ok := lookupFoldHost(table, raw)
		require.Equal(t, want, id, raw)
		require.Equal(t, want != 0, ok, raw)
	}
	_, ok := lookupFoldHost(nil, "a.fold.test")
	require.False(t, ok)
}

func TestLookupFoldHostDoesNotAllocate(t *testing.T) {
	table := map[string]uint32{"a.fold.test": 42}
	for _, raw := range []string{"a.fold.test", "A.FOLD.TEST:443", "miss.fold.test."} {
		require.Zero(t, testing.AllocsPerRun(100, func() { lookupFoldHost(table, raw) }), raw)
	}
}

func TestProvisionFoldHostsDropsEntriesInsteadOfFailing(t *testing.T) {
	before := counterValue(metricFoldHostsDropped)
	a := &StatsApp{logger: zap.NewNop(), FoldHosts: map[string]uint32{
		"a.fold.test": 42, "under_score.test": 9, "A.FOLD.TEST": 1, "b.fold.test.": 2, "c.fold.test:443": 3,
		"zero.fold.test": 0, "{env.APX_INTERNAL_KEY}": 4, "bücher.test": 5, "": 6,
		strings.Repeat("a", 254): 7,
	}}
	a.provisionFoldHosts()
	require.Equal(t, map[string]uint32{"a.fold.test": 42, "under_score.test": 9}, a.FoldHosts)
	require.Equal(t, before+8, counterValue(metricFoldHostsDropped))
}

func foldReq(host, vhostVar string) *http.Request {
	r := newRequestWithReplacer("GET", "http://"+host+"/x", vhostVar, nil)
	r.Host = host
	return r
}

func TestStatsHandlerFoldTableOwnsItsHosts(t *testing.T) {
	table := map[string]uint32{"a.fold.test": 42}
	setVar := func(value any) caddyhttp.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			caddyhttp.SetVar(r.Context(), "vhost_id", value)
			w.WriteHeader(200)
			return nil
		}
	}
	for name, tc := range map[string]struct {
		host string
		next caddyhttp.Handler
		want []uint32
	}{
		"empty var":              {"a.fold.test", nextHandler(200), []uint32{42}},
		"case and port":          {"A.FOLD.TEST:443", nextHandler(200), []uint32{42}},
		"rule clears the var":    {"a.fold.test", setVar(""), []uint32{42}},
		"rule writes the var":    {"a.fold.test", setVar("99"), []uint32{42}},
		"rule writes a non-int":  {"a.fold.test", setVar("x"), []uint32{42}},
		"rule writes a number":   {"a.fold.test", setVar(99), []uint32{42}},
		"host not in the table":  {"b.fold.test", setVar("99"), []uint32{99}},
		"no table entry, no var": {"b.fold.test", nextHandler(200), nil},
	} {
		t.Run(name, func(t *testing.T) {
			app := &fakeApp{}
			h := &StatsHandler{app: app, foldHosts: table}
			w := httptest.NewRecorder()
			require.NoError(t, h.ServeHTTP(w, foldReq(tc.host, ""), tc.next))
			var got []uint32
			for _, rec := range app.records {
				got = append(got, rec.k.VhostID)
			}
			require.Equal(t, tc.want, got)
		})
	}
}

func TestStatsHandlerFoldLookupUsesTheHostTheClientSent(t *testing.T) {
	table := map[string]uint32{"a.fold.test": 42, "b.fold.test": 43}
	rewrite := func(to string) caddyhttp.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			r.Host = to
			return nil
		}
	}
	app := &fakeApp{}
	h := &StatsHandler{app: app, foldHosts: table}
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), foldReq("a.fold.test", ""), rewrite("b.fold.test")))
	require.EqualValues(t, 42, app.records[0].k.VhostID)

	app = &fakeApp{}
	h = &StatsHandler{app: app, foldHosts: table}
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), foldReq("unknown.test", ""), rewrite("b.fold.test")))
	require.Empty(t, app.records, "rewriting a Host to a folded one must not claim it")
}

func TestStatsHandlerFoldCountsConflictsOnlyWhenTheVarDiffers(t *testing.T) {
	h := &StatsHandler{app: &fakeApp{}, foldHosts: map[string]uint32{"a.fold.test": 42}}
	before := counterValue(metricFoldHostVarConflicts)
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), foldReq("a.fold.test", ""), nextHandler(200)))
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), foldReq("a.fold.test", "42"), nextHandler(200)))
	require.Equal(t, before, counterValue(metricFoldHostVarConflicts))
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), foldReq("a.fold.test", "99"), nextHandler(200)))
	require.Equal(t, before+1, counterValue(metricFoldHostVarConflicts))
}

func TestStatsHandlerFoldAttributesBlockedAndChallengedRequests(t *testing.T) {
	app := &fakeApp{modeV2: true}
	h := &StatsHandler{app: app, foldHosts: map[string]uint32{"a.fold.test": 42}}
	blocked := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return caddyhttp.Error(http.StatusForbidden, errors.New("interruption triggered: 949110"))
	})
	require.Error(t, h.ServeHTTP(httptest.NewRecorder(), foldReq("a.fold.test", ""), blocked))
	require.Len(t, app.records, 1)
	require.EqualValues(t, 42, app.records[0].k.VhostID)
	require.Len(t, app.reqEvents, 1)
	require.EqualValues(t, 42, app.reqEvents[0].VhostID)
	require.Empty(t, app.reqEvents[0].Host)
	require.Equal(t, dispWafBlocked, app.reqEvents[0].Disposition)

	app = &fakeApp{modeV2: true}
	h = &StatsHandler{app: app, foldHosts: map[string]uint32{"a.fold.test": 42}}
	challenged := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		caddyhttp.SetVar(r.Context(), "apx_challenge_outcome", "issued")
		return nil
	})
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), foldReq("a.fold.test", ""), challenged))
	require.Len(t, app.reqEvents, 1)
	require.EqualValues(t, 42, app.reqEvents[0].VhostID)
	require.Equal(t, "a.fold.test", app.challenges[0].vhost, "challenge attempts stay keyed by host")
}

func TestFoldedRowCarriesTheRequestIDEvenWhenTheProxyNeverRan(t *testing.T) {
	app := &fakeApp{modeV2: true}
	h := &StatsHandler{app: app, foldHosts: map[string]uint32{"a.fold.test": 42}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://a.fold.test/x", nil)
	r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, &caddyhttp.Server{})
	require.NoError(t, h.ServeHTTP(w, r, nextHandler(403)))
	rows := app.reqEventSnapshot()
	require.Len(t, rows, 1)
	require.NotEmpty(t, rows[0].RequestID)
}

func TestStatsHandlerFoldSkipsMonitorProbes(t *testing.T) {
	app := &fakeApp{}
	h := &StatsHandler{app: app, foldHosts: map[string]uint32{"a.fold.test": 42}}
	r := foldReq("a.fold.test", "")
	r.Header.Set("apx-monitor", "true")
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, nextHandler(200)))
	require.Empty(t, app.records)
}

// ---- real Caddy ----

const foldHostsField = "fold_hosts"

type foldHarness struct {
	addr, logPath string
}

// customerHandlers are rules a customer could have, placed ahead of the
// catch-all, and catch-all proxy options. Each must not move attribution.
type foldRules struct {
	early  []any
	proxy  map[string]any
	errors []any
}

func vars(kv ...string) map[string]any {
	m := map[string]any{"handler": "vars"}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// startFold loads the shape Phoenix renders through caddy.Load: apx_stats
// outermost, a blocking route ahead of the catch-all, a real routed vhost, and a
// catch-all with an empty vhost_id and an X-Apx-Vhost-Id header.
func startFold(t *testing.T, origin, ingest string, table map[string]uint32, rules foldRules) *foldHarness {
	t.Helper()
	raw, h := foldConfig(t, origin, ingest, table, rules)
	require.NoError(t, caddy.Load(raw, true))
	return h
}

func foldConfig(t *testing.T, origin, ingest string, table map[string]uint32, rules foldRules) ([]byte, *foldHarness) {
	t.Helper()
	addr := freeLoopbackAddr(t)
	logPath := filepath.Join(t.TempDir(), "access.log")
	stats := map[string]any{
		"proxy_server_id": 89,
		"hash_salt":       "salt",
		"ingest": map[string]any{
			"url": ingest, "auth_token": "t", "flush_interval_ms": 50,
			"request_events": map[string]any{"enabled": true, "mode_v2": true},
		},
	}
	if table != nil {
		stats[foldHostsField] = table
	}
	proxy := map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": origin}}}
	for k, v := range rules.proxy {
		proxy[k] = v
	}
	// The generator sets this on every proxy step.
	headers, _ := proxy["headers"].(map[string]any)
	if headers == nil {
		headers = map[string]any{}
	}
	request, _ := headers["request"].(map[string]any)
	if request == nil {
		request = map[string]any{"set": map[string]any{}}
	}
	request["set"].(map[string]any)["X-Apx-Request-Id"] = []string{"{http.request.uuid}"}
	headers["request"] = request
	proxy["headers"] = headers
	routes := append([]any{}, rules.early...)
	routes = append(routes,
		map[string]any{"match": []any{map[string]any{"path": []string{"/blocked"}}}, "handle": []any{
			map[string]any{"handler": "error", "status_code": 403, "error": "interruption triggered: 949110"},
		}},
		map[string]any{"match": []any{map[string]any{"host": []string{"routed.test"}}}, "handle": []any{
			vars("vhost_id", "7"), map[string]any{"handler": "static_response", "status_code": 200, "body": "routed"},
		}, "terminal": true},
		map[string]any{"@id": "vhost_", "handle": []any{
			vars("vhost_id", ""),
			map[string]any{"handler": "headers", "request": map[string]any{"set": map[string]any{"X-Apx-Vhost-Id": []string{""}}}},
			proxy,
		}},
	)
	server := map[string]any{
		"listen":          []string{addr},
		"automatic_https": map[string]any{"disable": true},
		"logs":            map[string]any{"default_logger_name": "access"},
		"routes": []any{map[string]any{"handle": []any{
			map[string]any{"handler": "apx_stats"},
			map[string]any{"handler": "subroute", "routes": routes},
		}}},
	}
	if rules.errors != nil {
		server["errors"] = map[string]any{"routes": rules.errors}
	}
	raw, err := json.Marshal(map[string]any{
		"admin":   map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"storage": map[string]any{"module": "file_system", "root": t.TempDir()},
		"logging": map[string]any{"logs": map[string]any{
			"default": map[string]any{"level": "ERROR"},
			"access": map[string]any{"include": []string{"http.log.access.access"},
				"writer": map[string]any{"output": "file", "filename": logPath}},
		}},
		"apps": map[string]any{
			"apx_stats": stats,
			"http":      map[string]any{"grace_period": "1s", "servers": map[string]any{"edge": server}},
		},
	})
	require.NoError(t, err)
	return raw, &foldHarness{addr: addr, logPath: logPath}
}

type foldAnswer struct {
	Status int
	Header http.Header
	Body   string
}

func (h *foldHarness) ask(t *testing.T, host, path string, headers ...string) foldAnswer {
	t.Helper()
	req, err := http.NewRequest("GET", "http://"+h.addr+path, nil)
	require.NoError(t, err)
	req.Host = host
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	header := resp.Header.Clone()
	header.Del("Date")
	return foldAnswer{resp.StatusCode, header, string(body)}
}

// accessLog returns the access log with fields that differ on any two runs removed.
func (h *foldHarness) accessLog(t *testing.T, want int) []map[string]any {
	t.Helper()
	var entries []map[string]any
	require.Eventually(t, func() bool {
		raw, err := os.ReadFile(h.logPath)
		if err != nil {
			return false
		}
		entries = entries[:0]
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil {
				return false
			}
			delete(m, "ts")
			delete(m, "duration")
			// Reading the row's request id creates Caddy's lazy UUID, which a
			// configured server log then records. Generated configs have no server
			// logs block, and the read happens after the response.
			delete(m, "uuid")
			if req, ok := m["request"].(map[string]any); ok {
				delete(req, "remote_port")
			}
			if headers, ok := m["resp_headers"].(map[string]any); ok {
				delete(headers, "Date")
			}
			entries = append(entries, m)
		}
		return len(entries) == want
	}, 3*time.Second, 10*time.Millisecond)
	return entries
}

func foldOrigin(t *testing.T) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			w.Header().Set("Location", "/from-origin")
			w.WriteHeader(302)
			return
		}
		names := make([]string, 0, len(r.Header))
		for name := range r.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintf(w, "uri=%s host=%s\n", r.URL.RequestURI(), r.Host)
		for _, name := range names {
			if name == "X-Forwarded-For" || name == "Accept-Encoding" {
				continue
			}
			if name == "X-Apx-Request-Id" {
				fmt.Fprintf(w, "%s=set\n", name)
				continue
			}
			fmt.Fprintf(w, "%s=%q\n", name, r.Header[name])
		}
	}))
	return strings.TrimPrefix(srv.URL, "http://"), srv.Close
}

func normalizeFoldAnswer(a foldAnswer, origin string) foldAnswer {
	a.Body = strings.ReplaceAll(a.Body, origin, "ORIGIN")
	return a
}

// foldCounts sums request_count per vhost over everything shipped so far.
func foldCounts(posts func() []capturedPost) map[uint32]int {
	out := map[uint32]int{}
	for _, p := range posts() {
		for _, row := range p.rows {
			if count, ok := row["request_count"].(float64); ok {
				if _, health := row["configuration_key"]; health {
					continue
				}
				out[uint32(row["vhost_id"].(float64))] += int(count)
			}
		}
	}
	return out
}

func TestFoldHostTableThroughCaddy(t *testing.T) {
	origin, stopOrigin := foldOrigin(t)
	t.Cleanup(stopOrigin)
	ingest, posts := captureServer(t, http.StatusOK)
	t.Cleanup(ingest.Close)
	t.Cleanup(func() { _ = caddy.Stop() })

	readIdentity := "{http.vars.vhost_id}"
	deferredLocation := map[string]any{"handler": "headers", "response": map[string]any{
		"set": map[string]any{"Location": []string{"https://tenant.test/" + readIdentity}}, "delete": []string{"X-Unused"}}}
	cases := map[string]foldRules{
		"plain": {},
		// The P1 that ended the placeholder design: same Location with and without the table.
		"deferred rule reads the var": {early: []any{map[string]any{"handle": []any{deferredLocation}}}},
		"proxy headers read the var and any table name": {proxy: map[string]any{"headers": map[string]any{
			"request": map[string]any{"set": map[string]any{
				"X-Read": []string{readIdentity + "|{apx_fold_vhost_id}|{http.vars.fold_hosts}|{http.vars.apx_stats}"}}},
			"response": map[string]any{"set": map[string]any{"X-Read": []string{readIdentity}}},
		}}},
		"rule writes the var early": {early: []any{map[string]any{"handle": []any{vars("vhost_id", "99")}}}},
		// The P2 that showed writers matter too.
		"response handler clears the var": {proxy: map[string]any{"handle_response": []any{map[string]any{"routes": []any{map[string]any{"handle": []any{
			vars("vhost_id", ""), map[string]any{"handler": "static_response", "status_code": 200, "body": "cleared"}}}}}}}},
		"response handler rewrites the var": {proxy: map[string]any{"handle_response": []any{map[string]any{"routes": []any{map[string]any{"handle": []any{
			vars("vhost_id", "99"), map[string]any{"handler": "static_response", "status_code": 200, "body": "rewritten"}}}}}}}},
		// The CEL form that beat the scan.
		"CEL reads a computed name": {proxy: map[string]any{"handle_response": []any{map[string]any{"routes": []any{
			map[string]any{"match": []any{map[string]any{"expression": `""" " """ != "" && ph(req, ph(req, "http.request.header.X-Key")) == "42"`}},
				"handle": []any{map[string]any{"handler": "static_response", "status_code": 203}}},
			map[string]any{"handle": []any{map[string]any{"handler": "copy_response"}}},
		}}}}},
		"rule rewrites Host": {early: []any{map[string]any{"handle": []any{map[string]any{"handler": "headers", "request": map[string]any{"set": map[string]any{"Host": []string{"other.test"}}}}}}}},
	}
	corpus := []struct {
		host, path string
		headers    []string
	}{
		{"a.fold.test", "/orders?x=1", []string{"X-Key", "http.vars.vhost_id"}},
		{"A.FOLD.TEST", "/", nil},
		{"a.fold.test.", "/", nil},
		{"a.fold.test", "/redir", nil},
		{"a.fold.test", "/blocked", nil},
		{"unknown.fold.test", "/", nil},
		{"unknown.fold.test", "/blocked", nil},
		{"routed.test", "/", nil},
		{"a.fold.test", "/", []string{"X-Apx-Vhost-Id", "99"}},
		{"a.fold.test", "/", []string{"X-Evil", "{http.vars.vhost_id}"}},
	}
	table := map[string]uint32{"a.fold.test": 42, "unused.fold.test": 43}

	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			off := startFold(t, origin, ingest.URL, nil, rules)
			var offAnswers []foldAnswer
			for _, c := range corpus {
				offAnswers = append(offAnswers, normalizeFoldAnswer(off.ask(t, c.host, c.path, c.headers...), origin))
			}
			offLog := off.accessLog(t, len(corpus))

			on := startFold(t, origin, ingest.URL, table, rules)
			base := foldCounts(posts)
			for i, c := range corpus {
				got := normalizeFoldAnswer(on.ask(t, c.host, c.path, c.headers...), origin)
				require.Equal(t, offAnswers[i], got, "response %s %s", c.host, c.path)
			}
			onLog := on.accessLog(t, len(corpus))
			require.Equal(t, offLog, onLog, "access log")

			// Seven of the ten ask for a.fold.test in some form, the blocked one included.
			require.Eventually(t, func() bool { return foldCounts(posts)[42]-base[42] == 7 }, 3*time.Second, 10*time.Millisecond,
				"%v", foldCounts(posts))
			delta := foldCounts(posts)
			// Control: outside the table the var still decides, as it does today.
			wantOutside := 0
			if name == "rule writes the var early" || name == "response handler rewrites the var" {
				wantOutside = 1
			}
			require.Equal(t, wantOutside, delta[99]-base[99], "only a host outside the table reaches 99")
			require.Equal(t, base[43], delta[43], "an unused entry gets nothing")
		})
	}
}

func TestFoldHostTableBlockedRowsThroughCaddy(t *testing.T) {
	origin, stopOrigin := foldOrigin(t)
	t.Cleanup(stopOrigin)
	ingest, posts := captureServer(t, http.StatusOK)
	t.Cleanup(ingest.Close)
	t.Cleanup(func() { _ = caddy.Stop() })

	h := startFold(t, origin, ingest.URL, map[string]uint32{"a.fold.test": 42}, foldRules{})
	require.Equal(t, 403, h.ask(t, "A.Fold.Test", "/blocked").Status)
	require.Eventually(t, func() bool {
		for _, p := range posts() {
			for _, row := range p.rows {
				if row["_type"] == "request_event" && row["vhost_id"] == float64(42) && row["disposition"] == dispWafBlocked {
					return true
				}
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond)
	counts := foldCounts(posts)
	require.Equal(t, 1, counts[42])
	for _, p := range posts() {
		for _, row := range p.rows {
			if row["_type"] == "request_event" && row["vhost_id"] == float64(42) {
				require.NotEmpty(t, row["request_id"], "a blocked row correlates like a routed one")
			}
		}
	}
}

func TestFoldHostTableBadEntriesLoadAndServe(t *testing.T) {
	origin, stopOrigin := foldOrigin(t)
	t.Cleanup(stopOrigin)
	ingest, _ := captureServer(t, http.StatusOK)
	t.Cleanup(ingest.Close)
	t.Cleanup(func() { _ = caddy.Stop() })
	before := counterValue(metricFoldHostsDropped)
	h := startFold(t, origin, ingest.URL, map[string]uint32{"{env.APX_INTERNAL_KEY}": 1, "A.BAD": 2, "": 3, "ok.test": 4}, foldRules{})
	require.Equal(t, 200, h.ask(t, "ok.test", "/").Status)
	// Through caddy.Load, so the app's Provision is what dropped them.
	require.Equal(t, before+3, counterValue(metricFoldHostsDropped))
	require.EqualValues(t, 1, foldEntriesGauge(t))
}

func foldEntriesGauge(t *testing.T) float64 {
	t.Helper()
	var entries dto.Metric
	require.NoError(t, metricFoldHostEntries.Write(&entries))
	return entries.GetGauge().GetValue()
}

// A reload refused after the stats app provisioned must leave the live app
// published, count only its table, and hold nothing of the rejected one.
func TestFoldHostTableRefusedReloadLeavesTheLiveApp(t *testing.T) {
	origin, stopOrigin := foldOrigin(t)
	t.Cleanup(stopOrigin)
	ingest, posts := captureServer(t, http.StatusOK)
	t.Cleanup(ingest.Close)
	t.Cleanup(func() { _ = caddy.Stop() })

	live := map[string]uint32{"a.fold.test": 42}
	h := startFold(t, origin, ingest.URL, live, foldRules{})
	published := corazaApp.Load()
	require.Equal(t, live, published.FoldHostTable())
	require.EqualValues(t, 1, foldEntriesGauge(t))

	bad := foldRules{early: []any{map[string]any{"handle": []any{map[string]any{"handler": "apx_no_such_handler"}}}}}
	raw, _ := foldConfig(t, origin, ingest.URL, map[string]uint32{"a.fold.test": 50, "b.fold.test": 51}, bad)
	require.Error(t, caddy.Load(raw, true))

	require.Same(t, published, corazaApp.Load(), "the rejected app must not stay published")
	require.EqualValues(t, 1, foldEntriesGauge(t), "the gauge describes the table in use")
	h.ask(t, "a.fold.test", "/")
	require.Eventually(t, func() bool { return foldCounts(posts)[42] == 1 }, 3*time.Second, 10*time.Millisecond)
	require.Zero(t, foldCounts(posts)[50])
}

func TestFoldHostTableReloadSwapsTheTable(t *testing.T) {
	origin, stopOrigin := foldOrigin(t)
	t.Cleanup(stopOrigin)
	ingest, posts := captureServer(t, http.StatusOK)
	t.Cleanup(ingest.Close)
	t.Cleanup(func() { _ = caddy.Stop() })

	h := startFold(t, origin, ingest.URL, map[string]uint32{"a.fold.test": 42}, foldRules{})
	h.ask(t, "a.fold.test", "/")
	require.Eventually(t, func() bool { return foldCounts(posts)[42] == 1 }, 3*time.Second, 10*time.Millisecond)

	h = startFold(t, origin, ingest.URL, map[string]uint32{"a.fold.test": 50}, foldRules{})
	h.ask(t, "a.fold.test", "/")
	require.Eventually(t, func() bool { return foldCounts(posts)[50] == 1 }, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, 1, foldCounts(posts)[42])

	h = startFold(t, origin, ingest.URL, nil, foldRules{})
	h.ask(t, "a.fold.test", "/")
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, 1, foldCounts(posts)[50], "rollback stops attribution")
}

func BenchmarkLookupFoldHost(b *testing.B) {
	for _, n := range []int{181, 5_000, 100_000} {
		table := make(map[string]uint32, n)
		for i := 0; i < n; i++ {
			table[fmt.Sprintf("tenant-%06d.example-domain.test", i)] = uint32(i + 1)
		}
		for name, host := range map[string]string{"hit": "tenant-000042.example-domain.test", "upper": "TENANT-000042.EXAMPLE-DOMAIN.TEST:443", "miss": "elsewhere.example.test"} {
			b.Run(fmt.Sprintf("%d/%s", n, name), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					lookupFoldHost(table, host)
				}
			})
		}
	}
}
