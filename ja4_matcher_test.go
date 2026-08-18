package apxstats

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

// ja4TestConn is a net.Conn stub that only answers the address questions the
// matcher and the conn-context hook ask of it.
type ja4TestConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (c *ja4TestConn) LocalAddr() net.Addr  { return c.local }
func (c *ja4TestConn) RemoteAddr() net.Addr { return c.remote }

func newJA4TestConn(remote string) *ja4TestConn {
	ra, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		panic(err)
	}
	return &ja4TestConn{
		local:  &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443},
		remote: ra,
	}
}

// testHello is the minimal ClientHello every matcher test fingerprints.
func testHello() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1301},
		Extensions:        []uint16{0x0000},
		SignatureSchemes:  []tls.SignatureScheme{0x0403},
		SupportedVersions: []uint16{0x0304},
	}
}

func TestJA4Matcher_CaddyModuleID(t *testing.T) {
	got := (&JA4Matcher{}).CaddyModule().ID
	if string(got) != "tls.handshake_match.apx_ja4" {
		t.Errorf("module ID = %q, want tls.handshake_match.apx_ja4", got)
	}
}

func TestJA4Matcher_registered(t *testing.T) {
	m, err := caddy.GetModule("tls.handshake_match.apx_ja4")
	if err != nil {
		t.Fatalf("module not registered: %v", err)
	}
	if _, ok := m.New().(*JA4Matcher); !ok {
		t.Errorf("registered module is not *JA4Matcher")
	}
}

func TestJA4Matcher_emptyBlocklistNeverMatches(t *testing.T) {
	// Record-only mode. A caddytls ConnectionMatcher returning true SELECTS
	// its policy; with an empty blocklist this matcher must never do that, so
	// the catch-all policy always serves the connection.
	m := &JA4Matcher{app: newTestAppWithFP(10, 10), registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}

	if m.Match(testHello()) {
		t.Error("empty blocklist matched — record-only mode must never match")
	}
}

func TestJA4Matcher_blankBlocklistEntriesAreIgnored(t *testing.T) {
	// A config that emits [""] must stay record-only, not match a hello whose
	// fingerprint failed to compute.
	m := &JA4Matcher{Blocklist: []string{"", ""}, app: newTestAppWithFP(10, 10), registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(m.set) != 0 {
		t.Errorf("compiled set = %v, want empty", m.set)
	}
	if m.Match(testHello()) {
		t.Error("blank-only blocklist matched")
	}
}

func TestJA4Matcher_recordsEvenWhenNotMatching(t *testing.T) {
	app := newTestAppWithFP(10, 10)
	m := &JA4Matcher{app: app, registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}

	_ = m.Match(testHello())

	if len(app.fpMap) == 0 {
		t.Error("Match did not record the fingerprint")
	}
}

func TestJA4Matcher_blocklistedMatches(t *testing.T) {
	app := newTestAppWithFP(10, 10)
	hello := testHello()
	ja4 := ja4FromClientHello(hello)

	m := &JA4Matcher{Blocklist: []string{ja4}, app: app, registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !m.Match(hello) {
		t.Errorf("blocklisted JA4 %q did not match", ja4)
	}
}

func TestJA4Matcher_nonBlocklistedDoesNotMatch(t *testing.T) {
	app := newTestAppWithFP(10, 10)
	m := &JA4Matcher{Blocklist: []string{"t13d1516h2_deadbeefdead_cafecafecafe"}, app: app, registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if m.Match(testHello()) {
		t.Error("a non-blocklisted fingerprint matched")
	}
	if len(app.fpMap) == 0 {
		t.Error("a non-blocklisted fingerprint was not recorded")
	}
}

func TestJA4Matcher_nilHelloIsSafe(t *testing.T) {
	m := &JA4Matcher{app: newTestAppWithFP(10, 10), registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if m.Match(nil) {
		t.Error("nil hello matched")
	}
}

func TestJA4Matcher_fillsRegisteredHolder(t *testing.T) {
	app := newTestAppWithFP(10, 10)
	reg := newJA4Registry(8)
	m := &JA4Matcher{app: app, registry: reg}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}

	conn := newJA4TestConn("203.0.113.9:52000")
	key, ok := normalizeAddrPort(conn.RemoteAddr())
	if !ok {
		t.Fatal("normalizeAddrPort failed for the test conn")
	}
	holder := &ja4Holder{}
	reg.put(key, holder)

	hello := testHello()
	hello.Conn = conn
	want := ja4FromClientHello(hello)

	_ = m.Match(hello)

	if got := holder.get(); got != want {
		t.Errorf("holder = %q, want %q", got, want)
	}
}

func TestJA4Matcher_recordsIPFromConn(t *testing.T) {
	app := newTestAppWithFP(10, 10)
	m := &JA4Matcher{app: app, registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}

	hello := testHello()
	hello.Conn = newJA4TestConn("203.0.113.9:52000")
	_ = m.Match(hello)

	found := false
	for k := range app.fpIpMap {
		if k.IP == "203.0.113.9" {
			found = true
		}
	}
	if !found {
		t.Errorf("no (ja4, ip) row for the conn's remote IP; map = %v", app.fpIpMap)
	}
}

func TestJA4Matcher_noConnStillRecords(t *testing.T) {
	// A nil hello.Conn is an unusual embedding rather than a transport — both
	// crypto/tls (TCP) and quic-go (QUIC, via an injected stub conn) populate
	// it. Whatever produces one, the fingerprint must still be recorded, just
	// without an IP, and the matcher must not panic.
	app := newTestAppWithFP(10, 10)
	m := &JA4Matcher{app: app, registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if m.Match(testHello()) {
		t.Error("record-only matcher matched")
	}
	if len(app.fpMap) == 0 {
		t.Error("fingerprint not recorded when hello.Conn was nil")
	}
	if len(app.fpIpMap) != 0 {
		t.Errorf("an ip row was recorded without a conn: %v", app.fpIpMap)
	}
}

func TestJA4Matcher_ProvisionResolvesRegistryFromApp(t *testing.T) {
	app := newTestAppWithFP(10, 10)
	m := &JA4Matcher{app: app}
	if err := m.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if m.registry == nil {
		t.Fatal("Provision left the registry nil")
	}
	if m.registry != app.JA4Registry() {
		t.Error("Provision did not resolve the app's shared registry")
	}
	if m.set == nil {
		t.Error("Provision did not compile the blocklist set")
	}
}

// NOTE: the "Provision without the apx_stats app returns an error" path is not
// unit-testable here — caddy.Context.App dereferences the context's config,
// which a bare caddy.Context{} does not have, so the call panics inside caddy
// before our error branch runs. Building a full caddy config to reach it would
// test caddy's plumbing, not ours.

func TestStatsApp_JA4RegistryIsStable(t *testing.T) {
	a := &StatsApp{}
	first := a.JA4Registry()
	if first == nil {
		t.Fatal("JA4Registry returned nil")
	}
	if a.JA4Registry() != first {
		t.Error("JA4Registry returned a different registry on the second call")
	}
}

// --- handler wiring: accept goroutine -> registry -> matcher -> request ---

func TestStatsHandler_ja4ConnContextRoundTrip(t *testing.T) {
	h := &StatsHandler{app: &fakeApp{}}
	reg := h.ja4Registry()

	conn := newJA4TestConn("203.0.113.9:52001")
	ctx := h.ja4ConnContext(context.Background(), conn)

	if got := ja4FromContext(ctx); got != "" {
		t.Errorf("ja4 before the handshake = %q, want \"\"", got)
	}

	app := newTestAppWithFP(10, 10)
	m := &JA4Matcher{app: app, registry: reg}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	hello := testHello()
	hello.Conn = conn
	want := ja4FromClientHello(hello)
	_ = m.Match(hello)

	if got := ja4FromContext(ctx); got != want {
		t.Errorf("ja4 on the request context = %q, want %q", got, want)
	}
}

func TestStatsHandler_ja4ConnContextUnaddressableConn(t *testing.T) {
	h := &StatsHandler{app: &fakeApp{}}
	conn := &ja4TestConn{local: nil, remote: nil}
	ctx := h.ja4ConnContext(context.Background(), conn)
	if got := ja4FromContext(ctx); got != "" {
		t.Errorf("ja4 = %q, want \"\"", got)
	}
}

func TestStatsHandler_ja4ConnContextConcurrentAccepts(t *testing.T) {
	// A caddyhttp.Server runs one accept goroutine PER LISTENER, so the hook
	// has concurrent callers from the first connection — including on the
	// very first call, which resolves the registry. All of them must land in
	// the SAME registry or the matcher's fill misses.
	const goroutines = 64
	h := &StatsHandler{app: &fakeApp{}}

	start := make(chan struct{})
	var wg sync.WaitGroup
	regs := make([]*ja4Registry, goroutines)
	ctxs := make([]context.Context, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			conn := newJA4TestConn(fmt.Sprintf("203.0.113.9:%d", 20000+i))
			ctxs[i] = h.ja4ConnContext(context.Background(), conn)
			regs[i] = h.ja4Registry()
		}(i)
	}
	close(start)
	wg.Wait()

	for i, r := range regs {
		if r != regs[0] {
			t.Fatalf("goroutine %d resolved a different registry", i)
		}
	}

	// Every connection must still be fillable through the shared registry.
	for i := 0; i < goroutines; i++ {
		key := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(20000+i))
		want := fmt.Sprintf("t13d1516h2_%012d_ffffffffffff", i)
		if !regs[0].fill(key, want) {
			t.Errorf("conn %d: no holder registered", i)
			continue
		}
		if got := ja4FromContext(ctxs[i]); got != want {
			t.Errorf("conn %d: ja4 = %q, want %q", i, got, want)
		}
	}
}

// connContextFuncCount reads the registered-hook count off a caddyhttp.Server.
// The field is unexported and caddy exposes no reader, but Len() is legal on a
// read-only reflect.Value.
func connContextFuncCount(srv *caddyhttp.Server) int {
	return reflect.ValueOf(srv).Elem().FieldByName("connContextFuncs").Len()
}

// ja4Policy builds a connection policy carrying the apx_ja4 matcher, in the
// shape caddy's JSON decode produces before ConnectionPolicies.Provision loads
// the matcher modules.
func ja4Policy() *caddytls.ConnectionPolicy {
	return &caddytls.ConnectionPolicy{
		MatchersRaw: caddy.ModuleMap{ja4MatcherModuleKey: json.RawMessage(`{}`)},
	}
}

func TestStatsHandler_ProvisionRegistersConnContext(t *testing.T) {
	// Registration is gated on the matcher being present, so the policy has to
	// carry it — a bare policy is the flag-off fleet case, covered below.
	srv := &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{ja4Policy(), {}}}
	ctx := caddy.Context{Context: context.WithValue(context.Background(), caddyhttp.ServerCtxKey, srv)}

	h := &StatsHandler{app: &fakeApp{}}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if n := connContextFuncCount(srv); n != 1 {
		t.Errorf("connContextFuncs = %d, want 1", n)
	}
}

func TestStatsHandler_ProvisionSkipsServerWithoutMatcher(t *testing.T) {
	// The flag-off fleet case: a TLS-terminating server whose policies carry
	// no apx_ja4 matcher. Nothing can ever fill a holder there, so the accept
	// path must stay untouched — the image bump alone must not change it.
	srv := &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{{}}}
	ctx := caddy.Context{Context: context.WithValue(context.Background(), caddyhttp.ServerCtxKey, srv)}

	h := &StatsHandler{app: &fakeApp{}}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if n := connContextFuncCount(srv); n != 0 {
		t.Errorf("connContextFuncs = %d without an apx_ja4 policy, want 0", n)
	}
}

func TestServerHasJA4Matcher(t *testing.T) {
	tests := []struct {
		name string
		srv  *caddyhttp.Server
		want bool
	}{
		{"no policies", new(caddyhttp.Server), false},
		{"catch-all only", &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{{}}}, false},
		{"matcher policy first", &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{ja4Policy(), {}}}, true},
		{"matcher policy last", &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{{}, ja4Policy()}}, true},
		{"nil policy entry is skipped", &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{nil, ja4Policy()}}, true},
		{"a different matcher does not count", &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{{
			MatchersRaw: caddy.ModuleMap{"sni": json.RawMessage(`["example.com"]`)},
		}}}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverHasJA4Matcher(tc.srv); got != tc.want {
				t.Errorf("serverHasJA4Matcher = %v, want %v", got, tc.want)
			}
		})
	}
}

// ja4MatcherModuleKey must stay the last segment of the module ID, or the
// accept-path gate silently stops recognizing its own matcher.
func TestJA4MatcherModuleKeyMatchesModuleID(t *testing.T) {
	id := string((&JA4Matcher{}).CaddyModule().ID)
	if want := "tls.handshake_match." + ja4MatcherModuleKey; id != want {
		t.Errorf("module ID = %q, want %q", id, want)
	}
}

func TestStatsHandler_ProvisionSkipsNonTLSServer(t *testing.T) {
	// A plain :80 redirect server terminates no TLS, so its connections can
	// never reach the matcher. Registering there would churn the shared LRU
	// with holders that never fill and evict entries for live handshakes.
	srv := new(caddyhttp.Server) // no TLSConnPolicies
	ctx := caddy.Context{Context: context.WithValue(context.Background(), caddyhttp.ServerCtxKey, srv)}

	h := &StatsHandler{app: &fakeApp{}}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if n := connContextFuncCount(srv); n != 0 {
		t.Errorf("connContextFuncs = %d on a non-TLS server, want 0", n)
	}
}

func TestStatsHandler_ProvisionWithoutServerIsSafe(t *testing.T) {
	h := &StatsHandler{app: &fakeApp{}}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision without a server on the context: %v", err)
	}
}

func TestStatsHandler_recordStagesJA4FromContext(t *testing.T) {
	// End of the chain: accept hook -> registry -> matcher fill -> the value
	// record() stages on the recorder. Asserting record()'s EFFECT (not the
	// context it read from) is what makes deleting the read turn this red.
	h := &StatsHandler{app: &fakeApp{}}
	conn := newJA4TestConn("203.0.113.9:52002")
	connCtx := h.ja4ConnContext(context.Background(), conn)

	key, ok := normalizeAddrPort(conn.RemoteAddr())
	if !ok {
		t.Fatal("normalizeAddrPort failed")
	}
	if !h.ja4Registry().fill(key, "t13d1516h2_aaaabbbbcccc_ddddeeeeffff") {
		t.Fatal("fill found no holder for the registered conn")
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).WithContext(connCtx)
	w := &recorder{ResponseWriter: httptest.NewRecorder(), status: 200}
	h.record(r, w, time.Millisecond, nil)

	if w.ja4 != "t13d1516h2_aaaabbbbcccc_ddddeeeeffff" {
		t.Errorf("record() staged ja4 = %q, want the filled value", w.ja4)
	}
}

// --- Record: suppressing the duplicate write on L4 clusters ---

func TestJA4Matcher_recordFalseSkipsRecording(t *testing.T) {
	// On an l4_enabled cluster the FingerprintHandler already records this
	// exact handshake. fpIpMap is keyed (ja4, ip) on both paths, so recording
	// here too would double connection_count.
	app := newTestAppWithFP(10, 10)
	no := false
	m := &JA4Matcher{Record: &no, app: app, registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}

	hello := testHello()
	hello.Conn = newJA4TestConn("203.0.113.9:52003")
	_ = m.Match(hello)

	if len(app.fpMap) != 0 || len(app.fpIpMap) != 0 {
		t.Errorf("record:false still recorded: fpMap=%d fpIpMap=%d", len(app.fpMap), len(app.fpIpMap))
	}
}

func TestJA4Matcher_recordFalseStillHandsOff(t *testing.T) {
	// Suppressing the duplicate recording must NOT suppress the handoff: the
	// L4 recorder cannot reach the HTTP request context, so this is the only
	// path that puts a fingerprint on the request.
	app := newTestAppWithFP(10, 10)
	reg := newJA4Registry(8)
	no := false
	m := &JA4Matcher{Record: &no, app: app, registry: reg}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}

	conn := newJA4TestConn("203.0.113.9:52004")
	key, ok := normalizeAddrPort(conn.RemoteAddr())
	if !ok {
		t.Fatal("normalizeAddrPort failed for the test conn")
	}
	holder := &ja4Holder{}
	reg.put(key, holder)

	hello := testHello()
	hello.Conn = conn
	want := ja4FromClientHello(hello)
	_ = m.Match(hello)

	if got := holder.get(); got != want {
		t.Errorf("holder = %q, want %q — the handoff must survive record:false", got, want)
	}
}

func TestJA4Matcher_recordFalseStillBlocklists(t *testing.T) {
	// Record is about duplicate rows, not about matching.
	app := newTestAppWithFP(10, 10)
	hello := testHello()
	no := false
	m := &JA4Matcher{Blocklist: []string{ja4FromClientHello(hello)}, Record: &no, app: app, registry: newJA4Registry(8)}
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !m.Match(hello) {
		t.Error("record:false suppressed a blocklist match")
	}
}

func TestJA4Matcher_recordDefaultsOn(t *testing.T) {
	// An absent `record` key must RECORD. Defaulting to off would make a
	// cluster that omits the field silently produce no fingerprint rows.
	var m JA4Matcher
	if err := json.Unmarshal([]byte(`{}`), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !m.recordEnabled() {
		t.Error("recordEnabled() = false for a config with no `record` key, want true")
	}

	app := newTestAppWithFP(10, 10)
	m.app, m.registry = app, newJA4Registry(8)
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	_ = m.Match(testHello())
	if len(app.fpMap) == 0 {
		t.Error("default config did not record")
	}
}

func TestJA4Matcher_recordRoundTripsThroughJSON(t *testing.T) {
	for _, tc := range []struct {
		cfg  string
		want bool
	}{
		{`{"record":true}`, true},
		{`{"record":false}`, false},
	} {
		var m JA4Matcher
		if err := json.Unmarshal([]byte(tc.cfg), &m); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.cfg, err)
		}
		if got := m.recordEnabled(); got != tc.want {
			t.Errorf("%s: recordEnabled() = %v, want %v", tc.cfg, got, tc.want)
		}
	}
}

func TestStatsHandler_recordStagesEmptyJA4WithoutAHandshake(t *testing.T) {
	// No matcher ran. record() must stage "" rather than leave a stale value,
	// and must not panic on a context carrying no holder.
	h := &StatsHandler{app: &fakeApp{}}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := &recorder{ResponseWriter: httptest.NewRecorder(), status: 200, ja4: "stale"}
	h.record(r, w, time.Millisecond, nil)

	if w.ja4 != "" {
		t.Errorf("record() staged ja4 = %q, want \"\"", w.ja4)
	}
}
