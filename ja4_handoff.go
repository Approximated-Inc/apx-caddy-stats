package apxstats

import (
	"container/list"
	"context"
	"net"
	"net/netip"
	"sync"
)

// ja4Holder carries a fingerprint from the TLS handshake to the HTTP request.
// First write wins: a HelloRetryRequest exchange delivers a second, different
// ClientHello, and one connection must yield one fingerprint.
type ja4Holder struct {
	mu    sync.Mutex
	value string
	set   bool
}

func (h *ja4Holder) setOnce(v string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.set {
		return
	}
	h.value = v
	h.set = true
}

func (h *ja4Holder) get() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.value
}

type ja4CtxKeyType struct{}

var ja4CtxKey ja4CtxKeyType

// ja4WithContext installs a holder so the request side can read it later.
func ja4WithContext(ctx context.Context, h *ja4Holder) context.Context {
	return context.WithValue(ctx, ja4CtxKey, h)
}

// ja4FromContext returns the fingerprint for this connection, or "" when the
// handshake never reached the matcher. Callers MUST treat "" as normal — it is
// the state for every non-matcher cluster and every unmatched connection.
func ja4FromContext(ctx context.Context) string {
	h, _ := ctx.Value(ja4CtxKey).(*ja4Holder)
	if h == nil {
		return ""
	}
	return h.get()
}

// normalizeAddrPort canonicalizes an address for use as a handoff key. It
// always unmaps v4-mapped IPv6: the accept side and the matcher side can
// observe different string forms of the same address across a PROXY v2
// round-trip, and keying on the string form would silently miss.
func normalizeAddrPort(a net.Addr) (netip.AddrPort, bool) {
	if a == nil {
		return netip.AddrPort{}, false
	}
	if ta, ok := a.(*net.TCPAddr); ok {
		addr, ok := netip.AddrFromSlice(ta.IP)
		if !ok {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(addr.Unmap(), uint16(ta.Port)), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// ja4Registry hands holders from accept time to handshake time. Entries are
// short-lived — put on accept, removed on fill. A connection that never
// reaches the matcher leaks one entry, so this is an LRU rather than a plain
// map: bounded, oldest-evicted, and losing an entry only costs one
// fingerprint.
type ja4Registry struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[netip.AddrPort]*list.Element
}

type ja4Entry struct {
	key    netip.AddrPort
	holder *ja4Holder
}

func newJA4Registry(max int) *ja4Registry {
	if max <= 0 {
		max = 1
	}
	return &ja4Registry{max: max, ll: list.New(), m: make(map[netip.AddrPort]*list.Element)}
}

func (r *ja4Registry) put(key netip.AddrPort, h *ja4Holder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if el, ok := r.m[key]; ok {
		el.Value.(*ja4Entry).holder = h
		r.ll.MoveToFront(el)
		return
	}
	r.m[key] = r.ll.PushFront(&ja4Entry{key: key, holder: h})
	for r.ll.Len() > r.max {
		back := r.ll.Back()
		if back == nil {
			break
		}
		r.ll.Remove(back)
		delete(r.m, back.Value.(*ja4Entry).key)
	}
}

// fill sets the fingerprint on the registered holder and removes the entry.
// Reports whether a holder was found.
func (r *ja4Registry) fill(key netip.AddrPort, ja4 string) bool {
	r.mu.Lock()
	el, ok := r.m[key]
	if ok {
		r.ll.Remove(el)
		delete(r.m, key)
	}
	r.mu.Unlock()

	if !ok {
		return false
	}
	el.Value.(*ja4Entry).holder.setOnce(ja4)
	return true
}
