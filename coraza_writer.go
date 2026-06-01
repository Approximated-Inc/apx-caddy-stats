package apxstats

import (
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// corazaVhostHeader is the request header the Phoenix config-gen injects
// (set/overwrite) on every request so the WAF audit log can carry the
// vhost id. Compared case-insensitively — Coraza lowercases header keys
// internally, but we don't want to depend on that.
const corazaVhostHeader = "X-Apx-Vhost-Id"

// corazaApp is the single live StatsApp the audit-log writer hands
// detections to. RegisterAuditLogWriter is a GLOBAL factory with no app
// handle, and there is exactly one apx_stats app per process, so the app
// publishes itself here at Provision and clears it at Stop. The writer
// does an atomic load and no-ops if nil (unprovisioned / shutting down).
var corazaApp atomic.Pointer[StatsApp]

// corazaAuditWriter implements plugintypes.AuditLogWriter. Selected by
// the Coraza/Caddy directive `SecAuditLogType apx_stats` (emitted by the
// Phoenix config-gen). coraza-caddy fires ProcessLogging() in a defer on
// every transaction — including blocked ones — so Write runs for every
// request that matched at least one rule.
type corazaAuditWriter struct{}

// Init is a no-op — this writer needs no file/dir/formatter setup; it
// ships through the in-process apx_stats app.
func (*corazaAuditWriter) Init(plugintypes.AuditLogConfig) error { return nil }

// Close is a no-op — the apx_stats app owns the flush goroutine and HTTP
// client lifecycle; the writer holds no resources of its own.
func (*corazaAuditWriter) Close() error { return nil }

// Minimal structural views of the coraza audit-log interfaces, declaring
// ONLY the methods the writer reads. plugintypes.AuditLog and its kin
// satisfy these structurally (Go interface satisfaction is by method set),
// so Write accepts the real plugintypes.AuditLog while buildCorazaEvents
// — and the tests — work against these narrow views. This is required
// because the real plugintypes.AuditLogTransactionRequest.Args() returns
// *collections.ConcatKeyed, an unexported internal type that's unnameable
// from this package, so an external fake can't implement the full
// interface. The views sidestep that by not declaring Args() at all.
type (
	corazaAuditView interface {
		Transaction() corazaTxView
		Messages() []corazaMsgView
	}
	corazaTxView interface {
		UnixTimestamp() int64
		ID() string
		ServerID() string
		IsInterrupted() bool
		ClientIP() string
		Request() corazaReqView
	}
	corazaReqView interface {
		Method() string
		URI() string
		Headers() map[string][]string
	}
	corazaMsgView interface {
		Data() corazaMsgDataView
	}
	corazaMsgDataView interface {
		ID() int
		Severity() types.RuleSeverity
		Msg() string
		Data() string
		Tags() []string
	}
)

// --- adapters wrapping the real plugintypes.* into the narrow views ---

type auditLogAdapter struct{ al plugintypes.AuditLog }

func (a auditLogAdapter) Transaction() corazaTxView {
	tx := a.al.Transaction()
	if tx == nil {
		return nil
	}
	return txAdapter{tx}
}

func (a auditLogAdapter) Messages() []corazaMsgView {
	msgs := a.al.Messages()
	if len(msgs) == 0 {
		return nil
	}
	out := make([]corazaMsgView, 0, len(msgs))
	for _, m := range msgs {
		if m == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, msgAdapter{m})
	}
	return out
}

type txAdapter struct {
	tx plugintypes.AuditLogTransaction
}

func (t txAdapter) UnixTimestamp() int64 { return t.tx.UnixTimestamp() }
func (t txAdapter) ID() string           { return t.tx.ID() }
func (t txAdapter) ServerID() string     { return t.tx.ServerID() }
func (t txAdapter) IsInterrupted() bool  { return t.tx.IsInterrupted() }
func (t txAdapter) ClientIP() string     { return t.tx.ClientIP() }
func (t txAdapter) Request() corazaReqView {
	req := t.tx.Request()
	if req == nil {
		return nil
	}
	return reqAdapter{req}
}

type reqAdapter struct {
	req plugintypes.AuditLogTransactionRequest
}

func (r reqAdapter) Method() string               { return r.req.Method() }
func (r reqAdapter) URI() string                  { return r.req.URI() }
func (r reqAdapter) Headers() map[string][]string { return r.req.Headers() }

type msgAdapter struct{ msg plugintypes.AuditLogMessage }

func (m msgAdapter) Data() corazaMsgDataView {
	d := m.msg.Data()
	if d == nil {
		return nil
	}
	return d // *internal data implements the narrow view structurally
}

// Write receives the full structured detection for one transaction and
// appends ONE raw event per fired rule (al.Messages()) to the app's
// capped detection slice. No-ops if the app pointer is nil. Adapts the
// real plugintypes.AuditLog into the narrow views via auditLogAdapter.
func (*corazaAuditWriter) Write(al plugintypes.AuditLog) error {
	app := corazaApp.Load()
	if app == nil || al == nil {
		return nil
	}
	for _, ev := range buildCorazaEvents(auditLogAdapter{al}) {
		app.RecordCorazaDetection(ev)
	}
	return nil
}

// buildCorazaEvents extracts one corazaDetection per fired rule from an
// audit log view. Pure (no app handle, no side effects) so it can be
// tested in isolation. Returns nil for a nil/empty/transaction-less log.
func buildCorazaEvents(al corazaAuditView) []corazaDetection {
	if al == nil {
		return nil
	}
	tx := al.Transaction()
	if tx == nil {
		return nil
	}

	tsSec := corazaUnixNanoToSec(tx.UnixTimestamp())
	wasBlocked := tx.IsInterrupted()
	txID := tx.ID()
	host := tx.ServerID()
	clientIP := tx.ClientIP()

	var method, uri string
	var vhostID uint32
	if req := tx.Request(); req != nil {
		method = req.Method()
		uri = req.URI()
		vhostID = corazaVhostIDFromHeaders(req.Headers())
	}

	msgs := al.Messages()
	if len(msgs) == 0 {
		return nil
	}
	out := make([]corazaDetection, 0, len(msgs))
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		d := msg.Data()
		if d == nil {
			continue
		}
		out = append(out, corazaDetection{
			TsUnixSec:     tsSec,
			VhostID:       vhostID,
			RuleID:        uint32(nonNegInt(d.ID())),
			Severity:      corazaSeverityLabel(d.Severity()),
			RuleMsg:       d.Msg(),
			Tags:          d.Tags(),
			TxID:          txID,
			RequestURI:    uri,
			RequestMethod: method,
			RequestHost:   host,
			ClientIP:      clientIP,
			MatchData:     truncateBytes(d.Data(), corazaMatchDataMaxBytes),
			WasBlocked:    wasBlocked,
		})
	}
	return out
}

// corazaUnixNanoToSec converts the audit record's UnixTimestamp (which is
// NANOSECONDS in coraza v3.7.0) to whole Unix seconds, clamped to the
// uint32 range. Non-positive timestamps map to 0.
func corazaUnixNanoToSec(ns int64) uint32 {
	if ns <= 0 {
		return 0
	}
	sec := ns / 1_000_000_000
	if sec < 0 || sec > 0xFFFFFFFF {
		return 0
	}
	return uint32(sec)
}

// corazaVhostIDFromHeaders reads X-Apx-Vhost-Id from the audit log's
// request headers (case-insensitively — Coraza lowercases header keys
// internally, but we don't depend on that) and parses it to a uint.
// Returns 0 when the header is absent, the request-headers audit part is
// disabled, or the value doesn't parse — a rare fallback.
func corazaVhostIDFromHeaders(headers map[string][]string) uint32 {
	if len(headers) == 0 {
		return 0
	}
	for k, vals := range headers {
		if !strings.EqualFold(k, corazaVhostHeader) {
			continue
		}
		for _, v := range vals {
			if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32); err == nil {
				return uint32(n)
			}
		}
		return 0
	}
	return 0
}

// nonNegInt clamps a possibly-negative rule id to 0 (rule ids are
// non-negative in practice; this is defensive for the uint32 cast).
func nonNegInt(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// init registers the writer under the name "apx_stats" so the Coraza
// config directive `SecAuditLogType apx_stats` selects it. Registration
// runs before any WAF is built, so it's safe to wire here.
func init() {
	plugins.RegisterAuditLogWriter("apx_stats", func() plugintypes.AuditLogWriter {
		return &corazaAuditWriter{}
	})
}

// Interface guard.
var _ plugintypes.AuditLogWriter = (*corazaAuditWriter)(nil)
