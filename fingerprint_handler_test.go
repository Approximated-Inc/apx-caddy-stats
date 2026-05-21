package apxstats

import (
	"net"
	"testing"

	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func TestFingerprintHandler_CaddyModuleID(t *testing.T) {
	got := (&FingerprintHandler{}).CaddyModule().ID
	if string(got) != "layer4.handlers.apx_l4_fingerprint_stats" {
		t.Errorf("module ID = %q, want layer4.handlers.apx_l4_fingerprint_stats", got)
	}
}

// fakeNetConn wraps one end of a net.Pipe() but overrides RemoteAddr so
// that layer4.WrapConnection sees a real IP:port address (needed for
// readClientIPFromCx to parse a canonical IP). All other net.Conn
// methods delegate to the underlying pipe connection.
type fakeNetConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (f *fakeNetConn) RemoteAddr() net.Addr { return f.remoteAddr }

// fakeAddr is a net.Addr with a configurable string representation, used
// to supply a "host:port" remote address to fakeNetConn.
type fakeAddr struct{ s string }

func (a *fakeAddr) Network() string { return "tcp" }
func (a *fakeAddr) String() string  { return a.s }

// newTestConn builds a *layer4.Connection suitable for unit tests.
// remoteAddr is the address string (e.g. "1.2.3.4:5555") exposed via
// cx.RemoteAddr(). vars is an optional map of cx vars to pre-seed (e.g.
// tls_ja3 / tls_ja4). WrapConnection / SetVar / GetVar do no I/O on the
// underlying conn, so a plain net.Pipe() end needs no drain or deadline.
func newTestConn(t *testing.T, remoteAddr string, vars map[string]any) *layer4.Connection {
	t.Helper()
	in, out := net.Pipe()
	t.Cleanup(func() {
		_ = in.Close()
		_ = out.Close()
	})

	wrapped := &fakeNetConn{Conn: out, remoteAddr: &fakeAddr{s: remoteAddr}}
	cx := layer4.WrapConnection(wrapped, []byte{}, zap.NewNop())
	for k, v := range vars {
		cx.SetVar(k, v)
	}
	return cx
}

// fakeNext records that next.Handle ran.
type fakeNext struct{ called bool }

func (f *fakeNext) Handle(cx *layer4.Connection) error {
	f.called = true
	return nil
}

func TestFingerprintHandler_skipsWhenNoVars(t *testing.T) {
	a := newTestAppWithFP(5000, 10000)
	h := &FingerprintHandler{app: a}
	cx := newTestConn(t, "1.2.3.4:5555", nil) // no tls_ja3/tls_ja4 set
	next := &fakeNext{}
	if err := h.Handle(cx, next); err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("next.Handle must always run")
	}
	a.fpMu.Lock()
	n := len(a.fpMap)
	a.fpMu.Unlock()
	if n != 0 {
		t.Errorf("recorded %d rows for a connection with no fingerprint vars; want 0", n)
	}
}

func TestFingerprintHandler_recordsWhenVarsSet(t *testing.T) {
	a := newTestAppWithFP(5000, 10000)
	h := &FingerprintHandler{app: a}
	ja3 := "0123456789abcdef0123456789abcdef"
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	cx := newTestConn(t, "1.2.3.4:5555", map[string]any{"tls_ja3": ja3, "tls_ja4": ja4})
	next := &fakeNext{}
	if err := h.Handle(cx, next); err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("next.Handle must always run")
	}
	a.fpMu.Lock()
	nfp, nip := len(a.fpMap), len(a.fpIpMap)
	a.fpMu.Unlock()
	if nfp != 1 || nip != 1 {
		t.Errorf("recorded fp=%d ip=%d, want 1/1", nfp, nip)
	}
}

func TestFingerprintHandler_skipsWhenOnlyJA3(t *testing.T) {
	a := newTestAppWithFP(5000, 10000)
	h := &FingerprintHandler{app: a}
	ja3 := "0123456789abcdef0123456789abcdef"
	// tls_ja4 intentionally absent — only ja3 set
	cx := newTestConn(t, "1.2.3.4:5555", map[string]any{"tls_ja3": ja3})
	next := &fakeNext{}
	if err := h.Handle(cx, next); err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("next.Handle must always run even when skipping")
	}
	a.fpMu.Lock()
	n := len(a.fpMap)
	a.fpMu.Unlock()
	if n != 0 {
		t.Errorf("recorded %d rows when only ja3 was set; want 0 (either empty => skip)", n)
	}
}
