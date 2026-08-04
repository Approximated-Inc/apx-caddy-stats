package apxstats

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// --- fakes implementing the narrow coraza* views (NOT the full
// plugintypes interfaces, which carry an unnameable Args() return type) ---

type fakeAuditLog struct {
	tx       corazaTxView
	messages []corazaMsgView
}

func (f *fakeAuditLog) Transaction() corazaTxView { return f.tx }
func (f *fakeAuditLog) Messages() []corazaMsgView { return f.messages }

type fakeTx struct {
	unixTs      int64
	id          string
	serverID    string
	interrupted bool
	clientIP    string
	req         corazaReqView
}

func (t *fakeTx) UnixTimestamp() int64   { return t.unixTs }
func (t *fakeTx) ID() string             { return t.id }
func (t *fakeTx) ServerID() string       { return t.serverID }
func (t *fakeTx) IsInterrupted() bool    { return t.interrupted }
func (t *fakeTx) ClientIP() string       { return t.clientIP }
func (t *fakeTx) Request() corazaReqView { return t.req }

type fakeReq struct {
	method  string
	uri     string
	headers map[string][]string
}

func (r *fakeReq) Method() string               { return r.method }
func (r *fakeReq) URI() string                  { return r.uri }
func (r *fakeReq) Headers() map[string][]string { return r.headers }

type fakeMsg struct {
	data corazaMsgDataView
}

func (m *fakeMsg) Data() corazaMsgDataView { return m.data }

type fakeMsgData struct {
	id       int
	msg      string
	data     string
	severity types.RuleSeverity
	tags     []string
}

func (d *fakeMsgData) ID() int                      { return d.id }
func (d *fakeMsgData) Severity() types.RuleSeverity { return d.severity }
func (d *fakeMsgData) Msg() string                  { return d.msg }
func (d *fakeMsgData) Data() string                 { return d.data }
func (d *fakeMsgData) Tags() []string               { return d.tags }

// newCorazaTestApp builds a StatsApp wired only for the coraza detection
// track and publishes it via the package pointer. Returns a cleanup that
// clears the pointer.
func newCorazaTestApp(t *testing.T, maxEvents int) (*StatsApp, func()) {
	t.Helper()
	a := &StatsApp{ProxyServerIDValue: 89}
	a.cfg.corazaMaxEvents = maxEvents
	corazaApp.Store(a)
	return a, func() { corazaApp.Store(nil) }
}

func buildAuditLog(unixNs int64, id, host string, interrupted bool, headers map[string][]string, msgs ...*fakeMsgData) *fakeAuditLog {
	var messages []corazaMsgView
	for _, d := range msgs {
		messages = append(messages, &fakeMsg{data: d})
	}
	return &fakeAuditLog{
		tx: &fakeTx{
			unixTs:      unixNs,
			id:          id,
			serverID:    host,
			interrupted: interrupted,
			req:         &fakeReq{method: "POST", uri: "/x", headers: headers},
		},
		messages: messages,
	}
}

func TestBuildCorazaEvents_zeroMessages(t *testing.T) {
	al := buildAuditLog(1_700_000_000_000_000_000, "tx0", "h", false, nil)
	if got := buildCorazaEvents(al); len(got) != 0 {
		t.Errorf("events = %d, want 0", len(got))
	}
}

func TestBuildCorazaEvents_oneMessage(t *testing.T) {
	d := &fakeMsgData{id: 942100, msg: "SQLi", data: "' OR 1=1", severity: types.RuleSeverityCritical, tags: []string{"attack-sqli"}}
	al := buildAuditLog(1_700_000_000_000_000_000, "txA", "example.com", true,
		map[string][]string{"x-apx-vhost-id": {"7"}}, d)
	evs := buildCorazaEvents(al)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.RuleID != 942100 {
		t.Errorf("RuleID = %d, want 942100", ev.RuleID)
	}
	if ev.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", ev.Severity)
	}
	if ev.VhostID != 7 {
		t.Errorf("VhostID = %d, want 7", ev.VhostID)
	}
	if ev.TxID != "txA" {
		t.Errorf("TxID = %q, want txA", ev.TxID)
	}
	if ev.RequestHost != "example.com" {
		t.Errorf("RequestHost = %q, want example.com", ev.RequestHost)
	}
	if ev.RequestMethod != "POST" || ev.RequestURI != "/x" {
		t.Errorf("method/uri = %q/%q, want POST//x", ev.RequestMethod, ev.RequestURI)
	}
	if !ev.WasBlocked {
		t.Errorf("WasBlocked = false, want true (IsInterrupted)")
	}
	// ts: 1.7e18 ns -> 1.7e9 sec.
	if ev.TsUnixSec != 1_700_000_000 {
		t.Errorf("TsUnixSec = %d, want 1700000000", ev.TsUnixSec)
	}
}

func TestBuildCorazaEvents_nMessages_oneEventEach(t *testing.T) {
	d1 := &fakeMsgData{id: 1, severity: types.RuleSeverityWarning}
	d2 := &fakeMsgData{id: 2, severity: types.RuleSeverityError}
	d3 := &fakeMsgData{id: 3, severity: types.RuleSeverityNotice}
	al := buildAuditLog(1_700_000_000_000_000_000, "txN", "h", false, nil, d1, d2, d3)
	evs := buildCorazaEvents(al)
	if len(evs) != 3 {
		t.Fatalf("events = %d, want 3 (one per message)", len(evs))
	}
	if evs[0].RuleID != 1 || evs[1].RuleID != 2 || evs[2].RuleID != 3 {
		t.Errorf("rule ids out of order: %d %d %d", evs[0].RuleID, evs[1].RuleID, evs[2].RuleID)
	}
}

func TestBuildCorazaEvents_vhostHeaderCaseInsensitive(t *testing.T) {
	// Canonical-cased key must still parse (case-insensitive lookup).
	al := buildAuditLog(1, "tx", "h", false, map[string][]string{"X-Apx-Vhost-Id": {"42"}}, &fakeMsgData{id: 1})
	evs := buildCorazaEvents(al)
	if len(evs) != 1 || evs[0].VhostID != 42 {
		t.Fatalf("VhostID = %v, want 42", evs)
	}
}

func TestBuildCorazaEvents_vhostHeaderAbsentOrUnparseable(t *testing.T) {
	// Absent header -> 0.
	al1 := buildAuditLog(1, "tx", "h", false, nil, &fakeMsgData{id: 1})
	e1 := buildCorazaEvents(al1)
	// Unparseable value -> 0.
	al2 := buildAuditLog(1, "tx", "h", false, map[string][]string{"x-apx-vhost-id": {"notanumber"}}, &fakeMsgData{id: 2})
	e2 := buildCorazaEvents(al2)
	if e1[0].VhostID != 0 || e2[0].VhostID != 0 {
		t.Errorf("VhostID = %d/%d, want 0/0", e1[0].VhostID, e2[0].VhostID)
	}
}

func TestBuildCorazaEvents_matchDataTruncatedTo512(t *testing.T) {
	big := strings.Repeat("z", 1000)
	al := buildAuditLog(1, "tx", "h", false, nil, &fakeMsgData{id: 1, data: big})
	evs := buildCorazaEvents(al)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if len(evs[0].MatchData) != 512 {
		t.Errorf("MatchData len = %d, want 512", len(evs[0].MatchData))
	}
}

func TestBuildCorazaEvents_bufferedStringsDoNotPinLargeBackings(t *testing.T) {
	// Every attacker-length-controlled request field reaches the writer as
	// a SHORT slice of a potentially huge backing array: req.Method on
	// HTTP/1.1 is request_line[:i] (shares the full ~1MB line with the
	// URI), ServerID is a SplitHostPort slice of req.Host, MatchData can
	// be a substring of a large parsed buffer. Buffering those slices
	// uncloned pins the whole parent allocation while the governor's byte
	// accounting counts only the short length — a ~500x undercount that
	// defeats the governor under a flood. Build each field as a short
	// slice of a 1MB runtime backing and assert the buffered event owns
	// its bytes (different backing array).
	methodBacking := "POST" + strings.Repeat("m", 1<<20)
	uriBacking := "/login" + strings.Repeat("u", 1<<20)
	hostBacking := "example.com" + strings.Repeat("h", 1<<20)
	ipBacking := "203.0.113.7" + strings.Repeat("i", 1<<20)
	dataBacking := "' OR 1=1" + strings.Repeat("d", 1<<20)

	al := &fakeAuditLog{
		tx: &fakeTx{
			unixTs:   1,
			id:       "txPin",
			serverID: hostBacking[:11],
			clientIP: ipBacking[:11],
			req:      &fakeReq{method: methodBacking[:4], uri: uriBacking[:6]},
		},
		messages: []corazaMsgView{&fakeMsg{data: &fakeMsgData{id: 1, data: dataBacking[:8]}}},
	}
	evs := buildCorazaEvents(al)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]

	// Content must be intact...
	if ev.RequestMethod != "POST" || ev.RequestURI != "/login" ||
		ev.RequestHost != "example.com" || ev.ClientIP != "203.0.113.7" ||
		ev.MatchData != "' OR 1=1" {
		t.Fatalf("content mangled: %+v", ev)
	}
	// ...but every field must own its bytes, NOT share the parent backing.
	if unsafe.StringData(ev.RequestMethod) == unsafe.StringData(methodBacking) {
		t.Errorf("buffered RequestMethod shares the request-line backing; want a clone")
	}
	if unsafe.StringData(ev.RequestURI) == unsafe.StringData(uriBacking) {
		t.Errorf("buffered RequestURI shares its parent backing; want a clone")
	}
	if unsafe.StringData(ev.RequestHost) == unsafe.StringData(hostBacking) {
		t.Errorf("buffered RequestHost shares its parent backing; want a clone")
	}
	if unsafe.StringData(ev.ClientIP) == unsafe.StringData(ipBacking) {
		t.Errorf("buffered ClientIP shares its parent backing; want a clone")
	}
	if unsafe.StringData(ev.MatchData) == unsafe.StringData(dataBacking) {
		t.Errorf("buffered MatchData shares its parent backing; want a clone")
	}
}

func TestBuildCorazaEvents_methodWidthBounded(t *testing.T) {
	// A junk long method (any token chars pass net/http validation) must
	// not ride into the buffer at full width: capped to
	// corazaRequestMethodMaxBytes. Standard verbs are far below the cap.
	junk := strings.Repeat("X", 100)
	al := buildAuditLog(1, "tx", "h", false, nil, &fakeMsgData{id: 1})
	al.tx.(*fakeTx).req = &fakeReq{method: junk, uri: "/x"}
	evs := buildCorazaEvents(al)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if len(evs[0].RequestMethod) != corazaRequestMethodMaxBytes {
		t.Errorf("RequestMethod len = %d, want %d", len(evs[0].RequestMethod), corazaRequestMethodMaxBytes)
	}
}

func TestBuildCorazaEvents_wasBlockedFalse(t *testing.T) {
	al := buildAuditLog(1, "tx", "h", false, nil, &fakeMsgData{id: 1})
	evs := buildCorazaEvents(al)
	if evs[0].WasBlocked {
		t.Errorf("WasBlocked = true, want false (not interrupted)")
	}
}

func TestBuildCorazaEvents_clientIPFromTxNotXFF(t *testing.T) {
	// R12: the event's ClientIP must come from the audit-log transaction's
	// ClientIP() (PROXY-derived), NEVER from the X-Forwarded-For header,
	// which an attacker can forge. Set tx.ClientIP to a known value and
	// carry a DIFFERENT poison XFF on the request; the event must reflect
	// the tx value, proving XFF is never consulted.
	al := &fakeAuditLog{
		tx: &fakeTx{
			unixTs:   1_700_000_000_000_000_000,
			id:       "txIP",
			serverID: "example.com",
			clientIP: "198.51.100.9",
			req: &fakeReq{
				method:  "POST",
				uri:     "/x",
				headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4"}},
			},
		},
		messages: []corazaMsgView{&fakeMsg{data: &fakeMsgData{id: 1, severity: types.RuleSeverityWarning}}},
	}
	evs := buildCorazaEvents(al)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if evs[0].ClientIP != "198.51.100.9" {
		t.Errorf("ClientIP = %q, want 198.51.100.9 (tx IP, not XFF)", evs[0].ClientIP)
	}
}

func TestBuildCorazaEvents_nilAudit(t *testing.T) {
	if got := buildCorazaEvents(nil); got != nil {
		t.Errorf("nil audit = %v, want nil", got)
	}
}

func TestWrite_recordsThroughApp(t *testing.T) {
	a, cleanup := newCorazaTestApp(t, CorazaMaxEventsDefault)
	defer cleanup()
	w := &corazaAuditWriter{}
	// Drive the full Write path with a nil real audit log (covers the
	// app-non-nil + al-nil guard) and assert no events and no error.
	if err := w.Write(nil); err != nil {
		t.Fatalf("Write(nil) = %v, want nil", err)
	}
	if got := len(a.corazaSnapshot()); got != 0 {
		t.Errorf("events = %d, want 0", got)
	}
}

func TestWrite_noopWhenAppNil(t *testing.T) {
	corazaApp.Store(nil)
	w := &corazaAuditWriter{}
	// Must not panic and must return nil even with a nil audit log.
	if err := w.Write(nil); err != nil {
		t.Fatalf("Write returned error with nil app: %v", err)
	}
}

func TestRecordCorazaDetection_overflowCapDropsAndCounts(t *testing.T) {
	a, cleanup := newCorazaTestApp(t, 2) // tiny cap
	defer cleanup()
	a.RecordCorazaDetection(corazaDetection{RuleID: 1})
	a.RecordCorazaDetection(corazaDetection{RuleID: 2})
	a.RecordCorazaDetection(corazaDetection{RuleID: 3}) // dropped
	a.RecordCorazaDetection(corazaDetection{RuleID: 4}) // dropped

	a.corazaMu.Lock()
	n := len(a.corazaEvents)
	over := a.corazaOverflow
	a.corazaMu.Unlock()
	if n != 2 {
		t.Errorf("stored = %d, want 2 (cap enforced)", n)
	}
	if over != 2 {
		t.Errorf("corazaOverflow = %d, want 2", over)
	}
}

func TestCorazaSnapshot_takeAndReset(t *testing.T) {
	a, cleanup := newCorazaTestApp(t, CorazaMaxEventsDefault)
	defer cleanup()
	a.RecordCorazaDetection(corazaDetection{RuleID: 1})
	a.RecordCorazaDetection(corazaDetection{RuleID: 2})
	snap := a.corazaSnapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot = %d, want 2", len(snap))
	}
	// Second snapshot is empty (slice reset).
	if got := a.corazaSnapshot(); got != nil {
		t.Errorf("second snapshot = %v, want nil", got)
	}
}

// Init/Close are no-ops; assert they don't error.
func TestWriter_initCloseNoop(t *testing.T) {
	w := &corazaAuditWriter{}
	if err := w.Init(plugintypes.AuditLogConfig{}); err != nil {
		t.Errorf("Init = %v, want nil", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}

// Guard: the adapters must satisfy the narrow views, and the real
// plugintypes types must satisfy them structurally (compile-time check).
var (
	_ corazaAuditView   = auditLogAdapter{}
	_ corazaTxView      = txAdapter{}
	_ corazaReqView     = reqAdapter{}
	_ corazaMsgView     = msgAdapter{}
	_ corazaMsgDataView = plugintypes.AuditLogMessageData(nil)
)
