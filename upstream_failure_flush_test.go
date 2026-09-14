package apxstats

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/stretchr/testify/require"
)

// The HTTP/1 transport flushes its buffered writer after Request.write has
// already called WroteRequest. Keep the real transport and Caddy error mapping;
// only replace the connection to make a failure at that boundary deterministic.
func TestUpstreamFailureFinalBufferedFlush(t *testing.T) {
	ctx, err := caddy.ProvisionContext(&caddy.Config{Admin: &caddy.AdminConfig{Disabled: true}})
	require.NoError(t, err)
	ctx, cancel := caddy.NewContext(ctx)
	t.Cleanup(cancel)

	for _, tt := range []struct {
		name, want string
		cause      error
		status     uint16
	}{
		// net/http's remaining nothingWrittenError wrapper hides net.Error
		// from Caddy's status mapping; preserve its existing 502 status.
		{"timeout", "request_write_timeout", os.ErrDeadlineExceeded, 502},
		{"broken pipe", "request_write_error", &os.SyscallError{Syscall: "write", Err: syscall.EPIPE}, 502},
	} {
		t.Run(tt.name, func(t *testing.T) {
			local, peer := net.Pipe()
			releaseRead := make(chan struct{})
			t.Cleanup(func() {
				close(releaseRead)
				_ = local.Close()
				_ = peer.Close()
			})
			wroteRequest := make(chan error, 1)
			writeErr := &net.OpError{
				Op:     "write",
				Net:    "tcp",
				Source: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18081},
				Addr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18080},
				Err:    tt.cause,
			}
			conn := &upstreamFlushFailureConn{
				Conn:         local,
				writeErr:     writeErr,
				releaseRead:  releaseRead,
				wroteRequest: wroteRequest,
			}
			transport := &reverseproxy.HTTPTransport{}
			require.NoError(t, transport.Provision(ctx))
			transport.Transport.Proxy = nil
			transport.Transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
				return conn, nil
			}
			t.Cleanup(func() { require.NoError(t, transport.Cleanup()) })
			proxy := &reverseproxy.Handler{
				Transport: transport,
				Upstreams: reverseproxy.UpstreamPool{&reverseproxy.Upstream{Dial: "127.0.0.1:18080"}},
			}
			require.NoError(t, proxy.Provision(ctx))
			t.Cleanup(func() { require.NoError(t, proxy.Cleanup()) })

			request := httptest.NewRequest(http.MethodGet, "http://customer.example/", nil)
			request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
				WroteRequest: func(info httptrace.WroteRequestInfo) { wroteRequest <- info.Err },
			}))
			writer := httptest.NewRecorder()
			request = caddyhttp.PrepareRequest(request, caddy.NewReplacer(), writer, &caddyhttp.Server{})
			caddyhttp.SetVar(request.Context(), "vhost_id", "100")
			app := &fakeApp{modeV2: true}
			stats := &StatsHandler{app: app}
			err := stats.ServeHTTP(writer, request, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return proxy.ServeHTTP(w, r, nextHandler(404))
			}))

			require.ErrorIs(t, err, writeErr)
			var handlerErr caddyhttp.HandlerError
			require.ErrorAs(t, err, &handlerErr)
			var finalWriteErr *net.OpError
			require.ErrorAs(t, handlerErr.Err, &finalWriteErr)
			require.Equal(t, "write", finalWriteErr.Op)
			require.Equal(t, int32(1), conn.writeCalls.Load(), "failure must occur on the small request's first flush")
			require.True(t, conn.writeAfterTrace.Load(), "WroteRequest must precede the failed connection Write")
			select {
			case callbackErr := <-wroteRequest:
				require.NoError(t, callbackErr, "buffering succeeds before the later flush fails")
			default:
				t.Fatal("transport did not call WroteRequest")
			}
			rows := app.reqEventSnapshot()
			require.Len(t, rows, 1)
			require.Equal(t, tt.status, rows[0].Status)
			require.Equal(t, "served", rows[0].Disposition)
			t.Logf("WroteRequest=<nil>; final error=%T: %v; reason=%q", handlerErr.Err, handlerErr.Err, rows[0].UpstreamFailureReason)
			require.Equal(t, tt.want, rows[0].UpstreamFailureReason)
		})
	}
}

type upstreamFlushFailureConn struct {
	net.Conn
	writeErr        error
	releaseRead     <-chan struct{}
	wroteRequest    <-chan error
	writeCalls      atomic.Int32
	writeAfterTrace atomic.Bool
}

func (c *upstreamFlushFailureConn) Write([]byte) (int, error) {
	c.writeCalls.Add(1)
	c.writeAfterTrace.Store(len(c.wroteRequest) > 0)
	return 0, c.writeErr
}

func (c *upstreamFlushFailureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		// Let RoundTrip observe the write failure before the incidental read
		// error from closing the connection. Test cleanup releases the reader.
		<-c.releaseRead
	}
	return n, err
}
