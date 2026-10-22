package apxstats

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
	"github.com/stretchr/testify/require"
)

// Caddy 2.11.6+ hands every request to the route under an IdleTimeoutWriter
// (write_idle_timeout defaults to 1m). It offers FlushError and Unwrap but
// no Flush or Hijack, so only a recorder that walks Unwrap reaches the
// net/http writer that can flush, hijack or push.

// unwrapOnlyWriter is that shape, minus even the Push the real one promotes
// from caddyhttp.ResponseWriterWrapper.
type unwrapOnlyWriter struct{ w http.ResponseWriter }

func (u *unwrapOnlyWriter) Header() http.Header         { return u.w.Header() }
func (u *unwrapOnlyWriter) Write(b []byte) (int, error) { return u.w.Write(b) }
func (u *unwrapOnlyWriter) WriteHeader(code int)        { u.w.WriteHeader(code) }
func (u *unwrapOnlyWriter) Unwrap() http.ResponseWriter { return u.w }
func (u *unwrapOnlyWriter) FlushError() error           { return http.NewResponseController(u.w).Flush() }

// bareWriter can do nothing beyond http.ResponseWriter.
type bareWriter struct{ http.ResponseWriter }

// pushWriter is an HTTP/2-style writer that records server pushes.
type pushWriter struct {
	http.ResponseWriter
	pushed []string
}

func (p *pushWriter) Push(target string, _ *http.PushOptions) error {
	p.pushed = append(p.pushed, target)
	return nil
}

// hijackWriter is an HTTP/1-style writer that hands over one end of a pipe.
type hijackWriter struct {
	http.ResponseWriter
	conn net.Conn
}

func (h *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

func TestRecorderFlushReachesWriterBehindUnwrapOnlyWrapper(t *testing.T) {
	// Direct Flush serves callers that type-assert http.Flusher; Caddy's
	// reverse_proxy flushes through http.ResponseController.
	for name, flush := range map[string]func(*recorder) error{
		"Flush":              func(rec *recorder) error { rec.Flush(); return nil },
		"ResponseController": func(rec *recorder) error { return http.NewResponseController(rec).Flush() },
	} {
		t.Run(name, func(t *testing.T) {
			inner := httptest.NewRecorder()
			rec := &recorder{ResponseWriter: &unwrapOnlyWriter{inner}, status: 200}
			_, err := rec.Write([]byte("data: one\n\n"))
			require.NoError(t, err)
			require.NoError(t, flush(rec))
			require.True(t, inner.Flushed, "the flush must reach the writer under the wrapper")
		})
	}
}

func TestRecorderFlushErrorReportsUnflushableChain(t *testing.T) {
	rec := &recorder{ResponseWriter: &unwrapOnlyWriter{bareWriter{httptest.NewRecorder()}}, status: 200}
	require.ErrorIs(t, http.NewResponseController(rec).Flush(), http.ErrNotSupported)
}

func TestRecorderPushReachesPusherBehindUnwrapOnlyWrapper(t *testing.T) {
	inner := &pushWriter{ResponseWriter: httptest.NewRecorder()}
	rec := &recorder{ResponseWriter: &unwrapOnlyWriter{inner}, status: 200}
	require.NoError(t, rec.Push("/app.css", nil))
	require.Equal(t, []string{"/app.css"}, inner.pushed)

	noPusher := &recorder{ResponseWriter: &unwrapOnlyWriter{httptest.NewRecorder()}, status: 200}
	require.ErrorIs(t, noPusher.Push("/app.css", nil), http.ErrNotSupported)
}

func TestRecorderHijackReachesHijackerBehindUnwrapOnlyWrapper(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	inner := &hijackWriter{ResponseWriter: httptest.NewRecorder(), conn: server}
	rec := &recorder{ResponseWriter: &unwrapOnlyWriter{inner}, status: 200}
	rec.WriteHeader(http.StatusSwitchingProtocols)

	conn, brw, err := http.NewResponseController(rec).Hijack()
	require.NoError(t, err)
	require.Equal(t, server, conn)
	require.NotNil(t, brw)
	require.True(t, rec.hijacked)
	require.Equal(t, uint16(http.StatusSwitchingProtocols), finalStatus(rec, nil))
	require.Zero(t, responseBytes(rec), "post-hijack bytes bypass the recorder")
}

func TestRecorderHijackUnsupportedLeavesResponseUnhijacked(t *testing.T) {
	rec := &recorder{ResponseWriter: &unwrapOnlyWriter{httptest.NewRecorder()}, status: 200}
	_, _, err := rec.Hijack()
	require.ErrorIs(t, err, http.ErrNotSupported)
	require.False(t, rec.hijacked)
	require.False(t, rec.wrote)
}

// The tests below run the stats handler in front of Caddy's own
// reverse_proxy, under the unwrapOnlyWriter.

func TestStatsHandlerWebSocketUpgradeThroughUnwrapOnlyWriter(t *testing.T) {
	app := &fakeApp{modeV2: true}
	edge, done := statsEdge(t, &StatsHandler{app: app}, caddyProxy(t, upgradeEchoUpstream(t)), false)

	held := exchangeWebSocketFrames(t, edge.Listener.Addr().String(), "/socket")
	waitHandled(t, done)

	recs := app.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, uint16(http.StatusSwitchingProtocols), recs[0].k.Status)
	require.Equal(t, OriginUpstream, recs[0].k.Origin)
	require.Zero(t, recs[0].d.BytesOut, "post-upgrade bytes bypass the recorder; sizing the headers would fabricate bytes")
	require.GreaterOrEqual(t, recs[0].d.DurationUs, uint64(held.Microseconds()), "the row spans the tunnel's lifetime")
	evs := app.reqEventSnapshot()
	require.Len(t, evs, 1)
	require.Equal(t, uint16(http.StatusSwitchingProtocols), evs[0].Status)
	require.Zero(t, evs[0].BytesOut)
}

func TestStatsHandlerSSEFlushesThroughUnwrapOnlyWriter(t *testing.T) {
	for _, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
		t.Run(proto, func(t *testing.T) {
			upstream, release, stalled := sseUpstream(t)
			app := &fakeApp{modeV2: true}
			edge, done := statsEdge(t, &StatsHandler{app: app}, caddyProxy(t, upstream), proto == "HTTP/2.0")

			readSSE(t, edge.Client(), edge.URL+"/events", proto, release, stalled)
			waitHandled(t, done)

			recs := app.snapshot()
			require.Len(t, recs, 1)
			require.Equal(t, uint16(http.StatusOK), recs[0].k.Status)
			require.Equal(t, OriginUpstream, recs[0].k.Origin)
			require.Greater(t, recs[0].d.BytesOut, uint64(len(sseBody)), "streamed body bytes still count")
			evs := app.reqEventSnapshot()
			require.Len(t, evs, 1)
			require.Equal(t, uint16(http.StatusOK), evs[0].Status)
		})
	}
}

// TestCaddyServerStreamsThroughStatsHandler loads the handler into a real
// Caddy HTTP server, so it sits under whatever writer that Caddy version
// installs: nothing on 2.11.4, IdleTimeoutWriter on 2.11.6+. Rows go out
// through the app's real ingest path.
func TestCaddyServerStreamsThroughStatsHandler(t *testing.T) {
	ingest, posts := captureServer(t, http.StatusOK)
	t.Cleanup(ingest.Close)
	sse, release, stalled := sseUpstream(t)
	route := func(path, vhostID string, upstream *httptest.Server) map[string]any {
		return map[string]any{
			"match": []any{map[string]any{"path": []string{path}}},
			"handle": []any{
				map[string]any{"handler": "vars", "vhost_id": vhostID},
				map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": upstream.Listener.Addr().String()}}},
			},
		}
	}
	addr := freeLoopbackAddr(t)
	raw, err := json.Marshal(map[string]any{
		"admin":   map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"storage": map[string]any{"module": "file_system", "root": t.TempDir()},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"apx_stats": map[string]any{
				"proxy_server_id": 89,
				"ingest": map[string]any{
					"url":               ingest.URL,
					"auth_token":        "test-token",
					"flush_interval_ms": 100,
					"request_events":    map[string]any{"enabled": true, "mode_v2": true},
				},
			},
			"http": map[string]any{
				"grace_period": "1s",
				"servers": map[string]any{"edge": map[string]any{
					"listen":          []string{addr},
					"automatic_https": map[string]any{"disable": true},
					"routes": []any{map[string]any{"handle": []any{
						map[string]any{"handler": "apx_stats"},
						map[string]any{"handler": "subroute", "routes": []any{
							route("/socket", "101", upgradeEchoUpstream(t)),
							route("/events", "102", sse),
						}},
					}}},
				}},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, caddy.Load(raw, true))
	t.Cleanup(func() { _ = caddy.Stop() })

	var held time.Duration
	t.Run("WebSocket", func(t *testing.T) { held = exchangeWebSocketFrames(t, addr, "/socket") })
	t.Run("SSE", func(t *testing.T) {
		readSSE(t, &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}, "http://"+addr+"/events", "HTTP/1.1", release, stalled)
	})
	if t.Failed() {
		return
	}

	var socket, events map[string]any
	require.Eventually(t, func() bool {
		for _, post := range posts() {
			for _, row := range post.rows {
				if row["_type"] != "request_event" {
					continue
				}
				switch row["path"] {
				case "/socket":
					socket = row
				case "/events":
					events = row
				}
			}
		}
		return socket != nil && events != nil
	}, 10*time.Second, 50*time.Millisecond, "both requests must reach ingest as request_event rows")
	require.EqualValues(t, 101, socket["vhost_id"])
	require.EqualValues(t, http.StatusSwitchingProtocols, socket["status"])
	require.EqualValues(t, OriginUpstream, socket["origin"])
	require.EqualValues(t, 0, socket["bytes_out"])
	require.GreaterOrEqual(t, socket["duration_us"], float64(held.Microseconds()))
	require.EqualValues(t, 102, events["vhost_id"])
	require.EqualValues(t, http.StatusOK, events["status"])
	require.Greater(t, events["bytes_out"], float64(len(sseBody)))
}

const sseBody = "data: one\n\ndata: two\n\n"

// sseUpstream sends one event, flushes, and holds the stream open until
// release closes or 5s pass; stalled reports the latter.
func sseUpstream(t *testing.T) (*httptest.Server, chan struct{}, *atomic.Bool) {
	t.Helper()
	release := make(chan struct{})
	stalled := new(atomic.Bool)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		_ = http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			stalled.Store(true)
		}
		_, _ = io.WriteString(w, "data: two\n\n")
	}))
	t.Cleanup(srv.Close)
	return srv, release, stalled
}

// readSSE asserts the first event arrives while the upstream still holds
// the stream open, then releases it and reads the rest.
func readSSE(t *testing.T, client *http.Client, url, proto string, release chan struct{}, stalled *atomic.Bool) {
	t.Helper()
	start := time.Now()
	res, err := client.Get(url)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, proto, res.Proto)
	br := bufio.NewReader(res.Body)
	first, err := br.ReadString('\n')
	firstAt := time.Since(start)
	close(release)
	require.NoError(t, err)
	require.Equal(t, "data: one\n", first)
	require.False(t, stalled.Load(), "the first event arrived after %s, only once the upstream stopped waiting: no flush got through", firstAt)
	rest, err := io.ReadAll(br)
	require.NoError(t, err)
	require.Equal(t, sseBody, first+string(rest))
}

// upgradeEchoUpstream completes a WebSocket handshake and then echoes raw
// bytes until the client half-closes.
func upgradeEchoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			websocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		if brw.Flush() != nil {
			return
		}
		_, _ = io.Copy(conn, brw.Reader)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// exchangeWebSocketFrames upgrades a raw connection, round-trips three
// messages through the tunnel and closes it. It returns how long the
// tunnel was held open.
func exchangeWebSocketFrames(t *testing.T, addr, path string) time.Duration {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: customer.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, key)
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, res.StatusCode)
	require.Equal(t, websocketAccept(key), res.Header.Get("Sec-WebSocket-Accept"))

	opened := time.Now()
	for i := range 3 {
		msg := fmt.Sprintf("frame %d\n", i)
		_, err := io.WriteString(conn, msg)
		require.NoError(t, err)
		got := make([]byte, len(msg))
		_, err = io.ReadFull(br, got)
		require.NoError(t, err)
		require.Equal(t, msg, string(got), "the tunnel must relay both ways after the 101")
		time.Sleep(50 * time.Millisecond)
	}
	held := time.Since(opened)
	require.NoError(t, conn.Close())
	return held
}

// caddyProxy provisions Caddy's reverse_proxy against upstream.
func caddyProxy(t *testing.T, upstream *httptest.Server) *reverseproxy.Handler {
	t.Helper()
	ctx, err := caddy.ProvisionContext(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}})
	require.NoError(t, err)
	ctx, cancel := caddy.NewContext(ctx)
	t.Cleanup(cancel)
	transport := &reverseproxy.HTTPTransport{}
	require.NoError(t, transport.Provision(ctx))
	transport.Transport.Proxy = nil
	t.Cleanup(func() { _ = transport.Cleanup() })
	proxy := &reverseproxy.Handler{
		Transport: transport,
		Upstreams: reverseproxy.UpstreamPool{&reverseproxy.Upstream{Dial: upstream.Listener.Addr().String()}},
	}
	require.NoError(t, proxy.Provision(ctx))
	t.Cleanup(func() { _ = proxy.Cleanup() })
	return proxy
}

// statsEdge serves each request the way a Caddy 2.11.6+ server hands it to
// a route: under an Unwrap-only writer, prepared by Caddy, through the
// stats handler and then proxy. done receives the handler's result.
func statsEdge(t *testing.T, stats *StatsHandler, proxy *reverseproxy.Handler, h2 bool) (*httptest.Server, <-chan error) {
	t.Helper()
	done := make(chan error, 4)
	edge := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w = &unwrapOnlyWriter{w}
		r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, &caddyhttp.Server{})
		caddyhttp.SetVar(r.Context(), "vhost_id", "100")
		done <- stats.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return proxy.ServeHTTP(w, r, nextHandler(http.StatusNotFound))
		}))
	}))
	if h2 {
		edge.EnableHTTP2 = true
		edge.StartTLS()
	} else {
		edge.Start()
	}
	t.Cleanup(edge.Close)
	return edge, done
}

func waitHandled(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the stats handler did not return")
	}
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}
