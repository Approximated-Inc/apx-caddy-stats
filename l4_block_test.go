package apxstats

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/stretchr/testify/require"
)

func TestL4BlockRecordSeparateExactMinuteCounts(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(100))
	a.recordL4BlockAt("[::ffff:203.0.113.7]:443", "ip", 100)
	a.recordL4BlockAt("203.0.113.7", "ip", 100)
	a.recordL4BlockAt("203.0.113.7", "sni", 100)
	a.recordL4BlockAt("203.0.113.7", "ip", 101)
	a.recordL4BlockAt("bad", "ip", 100)
	a.recordL4BlockAt("203.0.113.7", "overflow", 100)
	snap := a.l4BlockSnapshot(102)
	require.Equal(t, map[l4BlockKey]uint64{
		{Minute: 100, IP: "203.0.113.7", Reason: "ip"}:  2,
		{Minute: 100, IP: "203.0.113.7", Reason: "sni"}: 1,
		{Minute: 101, IP: "203.0.113.7", Reason: "ip"}:  1,
	}, snap)
	require.Empty(t, a.l4BlockSnapshot(102))
	ip := a.l4IpSnapshot()
	require.Empty(t, ip.topkRows)
	require.Empty(t, ip.ipSni)
	require.Empty(t, ip.prefix)
	require.Empty(t, ip.sampled)
	require.Empty(t, a.drainL4SniRows())
	require.Empty(t, a.fingerprintSnapshot())
}

func TestL4BlockCapacityOverflowAndExistingKeys(t *testing.T) {
	a := &StatsApp{}
	for i := 0; i < l4BlockMaxKeys; i++ {
		a.recordL4BlockAt(fmt.Sprintf("2001:db8::%x", i+1), "ip", 100)
	}
	for i := 0; i < 7; i++ {
		a.recordL4BlockAt("203.0.113.10", "ja4", 101)
	}
	a.recordL4BlockAt("2001:db8::1", "ip", 100)
	require.Len(t, a.l4Blocks, l4BlockMaxKeys)
	snap := a.l4BlockSnapshot(102)
	require.Len(t, snap, l4BlockMaxKeys+1)
	require.Equal(t, uint64(2), snap[l4BlockKey{Minute: 100, IP: "2001:db8::1", Reason: "ip"}])
	require.Equal(t, uint64(7), snap[l4BlockKey{Minute: 102, IP: "::", Reason: "overflow"}])
	a.recordL4BlockAt("203.0.113.10", "ja4", 103)
	require.Len(t, a.l4BlockSnapshot(103), 1)
}

func TestL4BlockConcurrentRecordAndDrain(t *testing.T) {
	a := &StatsApp{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				a.recordL4BlockAt("203.0.113.8", "ja3", 100)
			}
		}()
	}
	var total uint64
	for i := 0; i < 10; i++ {
		for _, n := range a.l4BlockSnapshot(100) {
			total += n
		}
	}
	wg.Wait()
	for _, n := range a.l4BlockSnapshot(100) {
		total += n
	}
	require.Equal(t, uint64(4000), total)
}

func TestL4BlockBoundsIPWidthAndHandlerDoesNotGate(t *testing.T) {
	a := &StatsApp{}
	a.recordL4BlockAt("fe80::1%"+strings.Repeat("z", 20_000), "ip", 100)
	snap := a.l4BlockSnapshot(100)
	require.Equal(t, map[l4BlockKey]uint64{
		{Minute: 100, IP: "fe80::1", Reason: "ip"}: 1,
	}, snap)
	h := &L4BlockHandler{Reason: "ip", app: a}
	next := &fakeNext{}
	require.NoError(t, h.Handle(newTestConn(t, "bad-address", nil), next))
	require.True(t, next.called)
	require.Empty(t, a.l4BlockSnapshot(100))
}

type l4BlockNext func(*layer4.Connection) error

func (f l4BlockNext) Handle(cx *layer4.Connection) error { return f(cx) }

func TestL4BlockHandlerRecordsBeforeTerminalClose(t *testing.T) {
	a := &StatsApp{}
	h := &L4BlockHandler{Reason: "sni", app: a}
	cx := newTestConn(t, "203.0.113.9:4444", nil)
	wantErr := errors.New("terminal close result")
	called := false
	err := h.Handle(cx, l4BlockNext(func(got *layer4.Connection) error {
		called = true
		require.Same(t, cx, got)
		snap := a.l4BlockSnapshot(uint32(time.Now().Unix() / 60))
		require.Len(t, snap, 1)
		for k, n := range snap {
			require.Equal(t, "203.0.113.9", k.IP)
			require.Equal(t, "sni", k.Reason)
			require.Equal(t, uint64(1), n)
		}
		return wantErr
	}))
	require.True(t, called)
	require.ErrorIs(t, err, wantErr)
}

func TestL4BlockHandlerModuleAndValidation(t *testing.T) {
	_, err := caddy.GetModule("layer4.handlers.apx_l4_block_stats")
	require.NoError(t, err)
	for _, reason := range []string{"ip", "sni", "ja3", "ja4"} {
		require.NoError(t, (&L4BlockHandler{Reason: reason}).Validate())
		require.NoError(t, (&L4BlockHandler{Reason: reason, app: &StatsApp{}}).Provision(caddy.Context{}))
	}
	for _, reason := range []string{"", "overflow", "allowed", "IP"} {
		require.Error(t, (&L4BlockHandler{Reason: reason}).Validate())
	}
}

func TestL4BlockFlushWireAndEmptyDrain(t *testing.T) {
	srv, captured := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "secret")
	a.recordL4BlockAt("203.0.113.9", "ip", 100)
	a.l4BlockOverflow = 3
	a.flushOnce(0)
	a.flushOnce(0)
	posts := captured()
	require.Len(t, posts, 1)
	require.Len(t, posts[0].rows, 2)
	for _, row := range posts[0].rows {
		require.Equal(t, "l4_block", row["_type"])
		require.Equal(t, float64(42), row["proxy_server_id"])
		if row["reason"] == "ip" {
			require.Equal(t, "203.0.113.9", row["ip"])
			require.Equal(t, formatTs(100), row["ts"])
			require.Equal(t, float64(1), row["connection_count"])
		} else {
			require.Equal(t, "overflow", row["reason"])
			require.Equal(t, "::", row["ip"])
			require.Equal(t, float64(3), row["connection_count"])
		}
	}
}
