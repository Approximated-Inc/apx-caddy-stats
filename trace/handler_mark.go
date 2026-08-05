package apxtrace

import (
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// MarkHandler emits trace breadcrumbs in the middle of a handler chain.
// Phase "enter" emits route/edge_sequence_entered and snapshots request state.
// Phase "post" snapshots current state, diffs vs last snapshot, emits request_mutation.
type MarkHandler struct {
	Phase    string            `json:"phase,omitempty"`
	Label    string            `json:"label,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`

	app AppRef
}

// CaddyModule registers the mark handler.
func (*MarkHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_trace_mark",
		New: func() caddy.Module { return new(MarkHandler) },
	}
}

// Provision fetches the TraceApp reference. Not strictly required — events
// emitted via tc.App, which was captured in ServeHTTP of the outer handler —
// but we look it up for parity and early-failure if the app isn't configured.
func (h *MarkHandler) Provision(ctx caddy.Context) error {
	if h.app == nil {
		app, err := ctx.App("apx_trace")
		if err != nil {
			return fmt.Errorf("apx_trace_mark requires apx_trace app to be configured: %w", err)
		}
		ta, ok := app.(*TraceApp)
		if !ok {
			return fmt.Errorf("apx_trace_mark: unexpected app type %T", app)
		}
		h.app = ta
	}
	return nil
}

func (h *MarkHandler) UnmarshalCaddyfile(*caddyfile.Dispenser) error { return nil }

func (h *MarkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	tc := FromContext(r.Context())
	if tc == nil {
		return next.ServeHTTP(w, r)
	}

	now := time.Now().UnixNano()

	switch h.Phase {
	case "enter":
		evtType := EventRouteMatched
		if h.Label == "edge_sequence" {
			evtType = EventEdgeSequenceEntered
		}
		tc.App.EmitEvent(Event{
			Type:   evtType,
			TsNs:   now,
			Source: SourceCluster,
			Payload: map[string]any{
				"label":      h.Label,
				"metadata":   h.Metadata,
				"request_id": tc.RequestID,
			},
		}, tc.Token)
		tc.LastSnapshot = Snapshot(r)

	case "post":
		curr := Snapshot(r)
		diff := DiffSnapshots(tc.LastSnapshot, curr)
		tc.App.EmitEvent(Event{
			Type:   EventRequestMutation,
			TsNs:   now,
			Source: SourceCluster,
			Payload: map[string]any{
				"label":      h.Label,
				"metadata":   h.Metadata,
				"diff":       diff,
				"request_id": tc.RequestID,
			},
		}, tc.Token)
		tc.LastSnapshot = curr
	}

	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*MarkHandler)(nil)
	_ caddyfile.Unmarshaler       = (*MarkHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*MarkHandler)(nil)
)
