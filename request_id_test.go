package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func requestIDWireRow(t *testing.T, row requestEventRow) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	require.NoError(t, encodeRequestEventRow(gz, 42, row))
	require.NoError(t, gz.Close())
	zr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer zr.Close()
	var wire map[string]any
	require.NoError(t, json.NewDecoder(zr).Decode(&wire))
	return wire
}

func TestRequestIDRealCaddyProxyMatchesLogAcrossRetries(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}})
	require.NoError(t, err)
	ctx, cancel := caddy.NewContext(ctx)
	t.Cleanup(cancel)

	// Fail the first attempt at each path after receiving its header. This
	// exercises Caddy's retry loop with real HTTP transport, not a mock.
	var mu sync.Mutex
	attempts := map[string][]http.Header{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts[r.URL.Path] = append(attempts[r.URL.Path], r.Header.Clone())
		first := len(attempts[r.URL.Path]) == 1
		mu.Unlock()
		if first {
			conn, _, hijackErr := w.(http.Hijacker).Hijack()
			if hijackErr == nil {
				_ = conn.Close()
			}
			return
		}
		_, _ = io.WriteString(w, "origin body")
	}))
	t.Cleanup(upstream.Close)

	transport := &reverseproxy.HTTPTransport{}
	require.NoError(t, transport.Provision(ctx))
	transport.Transport.Proxy = nil
	transport.Transport.DisableKeepAlives = true
	t.Cleanup(func() { require.NoError(t, transport.Cleanup()) })
	proxy := &reverseproxy.Handler{Transport: transport}
	// Same JSON header configuration emitted by the control plane. A second
	// read verifies that placeholder reuse never generates another UUID.
	require.NoError(t, json.Unmarshal([]byte(`{"headers":{"request":{"set":{"X-Apx-Request-Id":["{http.request.uuid}"],"X-Test-Repeated-Id":["{http.request.uuid}"]}}},"load_balancing":{"retries":1}}`), proxy))
	proxy.Upstreams = reverseproxy.UpstreamPool{&reverseproxy.Upstream{Dial: strings.TrimPrefix(upstream.URL, "http://")}}
	require.NoError(t, proxy.Provision(ctx))
	t.Cleanup(func() { require.NoError(t, proxy.Cleanup()) })

	var loggedIDs []string
	for _, path := range []string{"/first", "/second"} {
		app := &fakeApp{modeV2: true}
		stats := &StatsHandler{app: app}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://customer.example"+path, nil)
		r.Header.Add("X-Apx-Request-Id", "client-spoof-one")
		r.Header.Add("X-Apx-Request-Id", "client-spoof-two")
		repl := caddy.NewReplacer()
		r = caddyhttp.PrepareRequest(r, repl, w, &caddyhttp.Server{})
		caddyhttp.SetVar(r.Context(), "vhost_id", "100")
		require.NoError(t, stats.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return proxy.ServeHTTP(w, r, nextHandler(404))
		})))
		require.Equal(t, 200, w.Code)
		require.Equal(t, "origin body", w.Body.String())
		retries, _ := repl.Get("http.reverse_proxy.retries")
		require.EqualValues(t, 1, retries, "must exercise Caddy's own retry loop")
		rows := app.reqEventSnapshot()
		require.Len(t, rows, 1)
		wire := requestIDWireRow(t, rows[0])
		requestID, ok := wire["request_id"].(string)
		require.True(t, ok, "v2 wire must carry request_id")
		id, err := uuid.Parse(requestID)
		require.NoError(t, err)
		require.Equal(t, uuid.Version(4), id.Version())
		require.Equal(t, "upstream", wire["origin"])
		require.NotContains(t, wire, "upstream_failure_reason", "recovered retry must not become a final proxy failure")

		mu.Lock()
		seen := attempts[path]
		mu.Unlock()
		require.Len(t, seen, 2)
		for _, headers := range seen {
			require.Equal(t, []string{requestID}, headers.Values("X-Apx-Request-Id"), "overwrite every spoofed value on every attempt")
			require.Equal(t, requestID, headers.Get("X-Test-Repeated-Id"))
		}
		loggedIDs = append(loggedIDs, requestID)
	}
	require.NotEqual(t, loggedIDs[0], loggedIDs[1], "separate incoming requests need distinct IDs")
}

func TestRequestIDUsesCaddyReplacerWithoutForwarding(t *testing.T) {
	for _, status := range []int{200, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			app := &fakeApp{modeV2: true}
			stats := &StatsHandler{app: app}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "https://customer.example/", nil)
			r.Header.Set("X-Apx-Request-Id", "client-spoof")
			repl := caddy.NewReplacer()
			r = caddyhttp.PrepareRequest(r, repl, w, &caddyhttp.Server{})
			caddyhttp.SetVar(r.Context(), "vhost_id", "100")
			require.NoError(t, stats.ServeHTTP(w, r, nextHandler(status)))
			rows := app.reqEventSnapshot()
			require.Len(t, rows, 1)
			wire := requestIDWireRow(t, rows[0])
			requestID, ok := wire["request_id"].(string)
			require.True(t, ok, "v2 wire must carry request_id even without a reverse proxy")
			_, err := uuid.Parse(requestID)
			require.NoError(t, err)
			want, _ := repl.Get("http.request.uuid")
			require.Equal(t, want, requestID)
			require.NotEqual(t, "client-spoof", requestID)
		})
	}
}

func TestRequestIDMissingPlaceholderNeverTrustsInboundHeader(t *testing.T) {
	app := &fakeApp{modeV2: true}
	stats := &StatsHandler{app: app}
	r := newRequestWithReplacer("GET", "/", "100", nil)
	r.Header.Set("X-Apx-Request-Id", "client-spoof")
	require.NoError(t, stats.ServeHTTP(httptest.NewRecorder(), r, nextHandler(200)))
	rows := app.reqEventSnapshot()
	require.Len(t, rows, 1)
	require.Equal(t, "", requestIDWireRow(t, rows[0])["request_id"])
}

func TestRequestIDMemoryAccounting(t *testing.T) {
	row := requestEventRow{V2: true, RequestID: "86aac198-bbb7-4bc3-b057-a57ee272a981"}
	without := row
	without.RequestID = ""
	require.Equal(t, 36, requestEventRowBytes(&row)-requestEventRowBytes(&without), "the memory governor must charge UUID backing bytes")
}
