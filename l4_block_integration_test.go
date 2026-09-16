package apxstats

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4close"
	_ "github.com/mholt/caddy-l4/modules/l4proxyprotocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Exercise JSON module loading, the actual PROXY decoder, route matching,
// terminal close and authenticated gzip delivery. Reading the socket peer
// instead of the decoded client, removing recording, or recording
// unmatched connections must change these externally observed rows.
func TestL4BlockProxyProtocolCloseAndDelivery(t *testing.T) {
	for _, reason := range []string{"ip", "sni", "ja3", "ja4"} {
		t.Run(reason, func(t *testing.T) {
			srv, captured := captureServer(t, 204)
			t.Cleanup(srv.Close)
			raw, err := json.Marshal(map[string]any{
				"proxy_server_id": 42,
				"ingest":          map[string]any{"url": srv.URL, "auth_token": "test-l4-secret", "flush_interval_ms": 3_600_000},
			})
			require.NoError(t, err)
			ctx, err := caddy.ProvisionContext(&caddy.Config{
				Admin:   &caddy.AdminConfig{Disabled: true},
				AppsRaw: caddy.ModuleMap{"apx_stats": raw},
			})
			require.NoError(t, err)
			ctx, cancel := caddy.NewContext(ctx)
			t.Cleanup(cancel)
			routes := layer4.RouteList{
				{HandlersRaw: []json.RawMessage{json.RawMessage(`{"handler":"proxy_protocol"}`)}},
				{
					MatcherSetsRaw: []caddy.ModuleMap{{"remote_ip": json.RawMessage(`{"ranges":["203.0.113.0/24","2001:db8::/32"]}`)}},
					HandlersRaw: []json.RawMessage{
						json.RawMessage(fmt.Sprintf(`{"handler":"apx_l4_block_stats","reason":%q}`, reason)),
						json.RawMessage(`{"handler":"close"}`),
					},
				},
			}
			require.NoError(t, routes.Provision(ctx))
			app, err := ctx.App("apx_stats")
			require.NoError(t, err)
			a := app.(*StatsApp)
			require.NoError(t, a.Start())
			t.Cleanup(func() { require.NoError(t, a.Stop()) })
			chain := routes.Compile(zap.NewNop(), time.Second, layer4.HandlerFunc(func(cx *layer4.Connection) error {
				defer cx.Close()
				_, err := io.WriteString(cx, "allowed\n")
				return err
			}))
			for _, tc := range []struct{ header, response string }{
				{"PROXY TCP4 203.0.113.9 192.0.2.1 5555 443\r\n", ""},
				{"PROXY TCP6 2001:db8::9 2001:db8:ffff::1 5555 443\r\n", ""},
				{"PROXY TCP4 198.51.100.9 192.0.2.1 5555 443\r\n", "allowed\n"},
			} {
				client, server := net.Pipe()
				t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
				require.NoError(t, client.SetDeadline(time.Now().Add(3*time.Second)))
				done := make(chan error, 1)
				go func() {
					defer server.Close()
					done <- chain.Handle(layer4.WrapConnection(server, nil, zap.NewNop()))
				}()
				_, err := io.WriteString(client, tc.header)
				require.NoError(t, err)
				body, err := io.ReadAll(client)
				require.NoError(t, err, "connection must close without waiting for a deadline")
				require.Equal(t, tc.response, string(body))
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(3 * time.Second):
					t.Fatal("L4 route did not finish after closing the connection")
				}
			}
			// Stop must deliver the final partial window, including a batch
			// containing only block rows (the normal HTTP counters are empty).
			require.NoError(t, a.Stop())
			posts := captured()
			require.Len(t, posts, 1)
			require.Equal(t, "test-l4-secret", posts[0].headers.Get("apx-key"))
			require.Len(t, posts[0].rows, 2)
			counts := map[string]float64{}
			for _, row := range posts[0].rows {
				require.Equal(t, "l4_block", row["_type"])
				require.Equal(t, float64(42), row["proxy_server_id"])
				require.Equal(t, reason, row["reason"])
				counts[row["ip"].(string)] = row["connection_count"].(float64)
			}
			require.Equal(t, map[string]float64{"203.0.113.9": 1, "2001:db8::9": 1}, counts)
		})
	}
}
