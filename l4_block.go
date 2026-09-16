package apxstats

import (
	"compress/gzip"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

const l4BlockMaxKeys = 10_000

type l4BlockKey struct {
	Minute uint32
	IP     string
	Reason string
}

// L4BlockHandler records a configured block match immediately before close.
// It does not read TLS bytes or feed the existing L4 detection counters.
type L4BlockHandler struct {
	Reason string `json:"reason"`
	app    *StatsApp
}

func (*L4BlockHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.apx_l4_block_stats",
		New: func() caddy.Module { return new(L4BlockHandler) },
	}
}

func (h *L4BlockHandler) Provision(ctx caddy.Context) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if h.app != nil {
		return nil
	}
	app, err := ctx.App("apx_stats")
	if err != nil {
		return fmt.Errorf("apx_l4_block_stats requires apx_stats: %w", err)
	}
	var ok bool
	h.app, ok = app.(*StatsApp)
	if !ok {
		return fmt.Errorf("apx_l4_block_stats: unexpected app type %T", app)
	}
	return nil
}

func (h *L4BlockHandler) Validate() error {
	if !validL4BlockReason(h.Reason) {
		return fmt.Errorf("apx_l4_block_stats reason must be ip, sni, ja3, or ja4")
	}
	return nil
}

func validL4BlockReason(reason string) bool {
	switch reason {
	case "ip", "sni", "ja3", "ja4":
		return true
	default:
		return false
	}
}

func (h *L4BlockHandler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	h.app.recordL4BlockAt(readClientIPFromCx(cx), h.Reason, uint32(time.Now().Unix()/60))
	return next.Handle(cx)
}

func (a *StatsApp) recordL4BlockAt(ip, reason string, minute uint32) {
	if a == nil || !validL4BlockReason(reason) {
		return
	}
	canonical, _, _, ok := canonicalIPAndPrefix(ip)
	if !ok {
		return
	}
	// Scope zones are connection-local metadata, not a wire IP dimension.
	addr, err := netip.ParseAddr(canonical)
	if err != nil {
		return
	}
	canonical = addr.WithZone("").String()
	key := l4BlockKey{Minute: minute, IP: canonical, Reason: reason}
	a.l4BlockMu.Lock()
	defer a.l4BlockMu.Unlock()
	if _, exists := a.l4Blocks[key]; !exists {
		if len(a.l4Blocks) >= l4BlockMaxKeys {
			a.l4BlockOverflow++
			return
		}
		if a.l4Blocks == nil {
			a.l4Blocks = make(map[l4BlockKey]uint64)
		}
		key.Reason = strings.Clone(reason)
	}
	a.l4Blocks[key]++
}

// Overflow uses one counter, timestamped at flush, to bound all auxiliary state.
// Its sentinel IP is not an observed client and must never be bot-classified.
func (a *StatsApp) l4BlockSnapshot(flushMinute uint32) map[l4BlockKey]uint64 {
	a.l4BlockMu.Lock()
	defer a.l4BlockMu.Unlock()
	snap := a.l4Blocks
	a.l4Blocks = nil
	if a.l4BlockOverflow > 0 {
		if snap == nil {
			snap = make(map[l4BlockKey]uint64)
		}
		snap[l4BlockKey{Minute: flushMinute, IP: "::", Reason: "overflow"}] = a.l4BlockOverflow
		a.l4BlockOverflow = 0
	}
	return snap
}

func encodeL4BlockRow(w *gzip.Writer, ps uint32, key l4BlockKey, count uint64) error {
	var b strings.Builder
	b.Grow(160)
	b.WriteByte('{')
	writeString(&b, "_type", "l4_block")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(key.Minute))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "ip", key.IP)
	b.WriteByte(',')
	writeString(&b, "reason", key.Reason)
	b.WriteByte(',')
	writeUint64(&b, "connection_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

var (
	_ caddy.Provisioner  = (*L4BlockHandler)(nil)
	_ caddy.Validator    = (*L4BlockHandler)(nil)
	_ layer4.NextHandler = (*L4BlockHandler)(nil)
)
