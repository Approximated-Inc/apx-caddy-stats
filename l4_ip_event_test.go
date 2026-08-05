package apxstats

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// l4IpEnabled is the helper used by every Phase 2 test to flip the
// gating flag. RecordL4Ip / flush gating both share the
// `l4SniMaxKeys > 0` check from Phase 1 — no separate config knob.
func l4IpEnabled(cap int) func(*StatsApp) {
	return func(a *StatsApp) {
		a.Ingest.L4SniMaxKeys = cap
	}
}

func TestRecordL4Ip_BoundsSniWidthInKeys(t *testing.T) {
	// The (IP, SNI, outcome) composite keys are built fresh (no backing
	// shared with the caller), but their WIDTH embeds the SNI — a junk
	// 64KB SNI flood would balloon the count-capped map. Same 255-byte
	// bound as the L4 SNI track.
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(100))
	a.cfg.l4SniMaxKeys = 100

	long := strings.Repeat("s", 300)
	a.RecordL4Ip("203.0.113.7:4444", long)

	snap := a.l4IpSnapshot()
	require.Len(t, snap.ipSni, 1)
	want := l4IpSniKeyString("203.0.113.7", long[:255], L4IpOutcomeAllowed)
	for k := range snap.ipSni {
		require.Equal(t, want, k)
	}
}

func TestRecordL4Ip_DisabledWhenCapZero(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret")
	// cap defaults to 0 → per-IP tracking disabled.

	for i := 0; i < 100; i++ {
		a.RecordL4Ip("10.0.0.1", "example.com")
	}

	snap := a.l4IpSnapshot()
	require.Empty(t, snap.topkRows)
	require.Empty(t, snap.sampled)
	require.Empty(t, snap.prefix)
	require.Empty(t, snap.ipSni)
}

func TestRecordL4Ip_EmptyIPDropped(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(100))
	a.cfg.l4SniMaxKeys = 100

	a.RecordL4Ip("", "example.com")
	a.RecordL4Ip("not-an-ip", "example.com")

	snap := a.l4IpSnapshot()
	require.Empty(t, snap.topkRows, "empty/unparseable IPs must drop silently")
	require.Empty(t, snap.sampled)
	require.Empty(t, snap.prefix)
	require.Empty(t, snap.ipSni)
}

func TestRecordL4Ip_TopKRoundTrip(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(100))
	a.cfg.l4SniMaxKeys = 100

	// Push three IPs with distinct frequencies — TopK is exact for
	// inputs well under the K=1000 budget so we can assert counts.
	for i := 0; i < 100; i++ {
		a.RecordL4Ip("10.0.0.1", "a.example.com")
	}
	for i := 0; i < 50; i++ {
		a.RecordL4Ip("10.0.0.2", "b.example.com")
	}
	for i := 0; i < 10; i++ {
		a.RecordL4Ip("10.0.0.3", "c.example.com")
	}

	snap := a.l4IpSnapshot()
	require.Len(t, snap.topkRows, 3, "expected three distinct IPs in TopK")

	counts := map[string]uint64{}
	for _, r := range snap.topkRows {
		counts[r.IP] = r.Count
	}
	require.Equal(t, uint64(100), counts["10.0.0.1"])
	require.Equal(t, uint64(50), counts["10.0.0.2"])
	require.Equal(t, uint64(10), counts["10.0.0.3"])
}

func TestRecordL4Ip_TopKResetAfterSnapshot(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(100))
	a.cfg.l4SniMaxKeys = 100

	a.RecordL4Ip("10.0.0.1", "x.example.com")
	a.RecordL4Ip("10.0.0.1", "x.example.com")
	_ = a.l4IpSnapshot()

	snap := a.l4IpSnapshot()
	require.Empty(t, snap.topkRows, "TopK must reset after drain")
	require.Empty(t, snap.sampled)
	require.Empty(t, snap.prefix)
	require.Empty(t, snap.ipSni)
}

func TestRecordL4Ip_SamplingHonoursDenom(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(10_000))
	a.cfg.l4SniMaxKeys = 10_000

	expected := map[string]bool{}
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		a.RecordL4Ip(ip, "x.example.com")
		// Recompute the canonical form the way RecordL4Ip does — the
		// sampleIP fn hashes the post-canonicalize string, not the raw
		// input. They're identical for these dotted-quad inputs but
		// being explicit guards against subtle mismatches.
		canonical, _, _, ok := canonicalIPAndPrefix(ip)
		if !ok {
			continue
		}
		if hashIPForTest(canonical)%sampleDenom == 0 {
			expected[canonical] = true
		}
	}

	snap := a.l4IpSnapshot()

	// Every sampled IP in expected must appear; nothing outside it may.
	for ip := range snap.sampled {
		require.True(t, expected[ip], "IP %s appeared in sampled set but doesn't match hash%%denom==0", ip)
	}
	for ip := range expected {
		require.Contains(t, snap.sampled, ip, "expected IP %s missing from sampled set", ip)
	}
}

func hashIPForTest(ip string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(ip))
	return h.Sum64()
}

func TestRecordL4Ip_PrefixV4Slash24(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(100))
	a.cfg.l4SniMaxKeys = 100

	a.RecordL4Ip("203.0.113.5", "a.example.com")
	a.RecordL4Ip("203.0.113.42", "b.example.com")
	a.RecordL4Ip("203.0.113.250", "c.example.com")

	snap := a.l4IpSnapshot()

	wantKey := l4IpPrefixKeyString("203.0.113.0", 24)
	require.Equal(t, uint64(3), snap.prefix[wantKey],
		"three IPs in 203.0.113.0/24 should collapse to one prefix counter at 3")

	// /56 prefix should not appear for IPv4 inputs.
	for k := range snap.prefix {
		_, plen, ok := splitPrefixKey(k)
		require.True(t, ok)
		require.Equal(t, uint8(24), plen, "IPv4 input must use /24")
	}
}

func TestRecordL4Ip_PrefixV6Slash56(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(100))
	a.cfg.l4SniMaxKeys = 100

	// Two v6 addresses that share a /56 — they differ only in the low
	// 72 bits. 2001:db8:1234:56xx::/56.
	a.RecordL4Ip("2001:db8:1234:5600::1", "a.example.com")
	a.RecordL4Ip("2001:db8:1234:5600::ffff", "b.example.com")
	// Different /56 — bumps the third byte of the prefix.
	a.RecordL4Ip("2001:db8:1234:5700::1", "c.example.com")

	snap := a.l4IpSnapshot()

	// Build expected key the same way the encoder does.
	wantSameKey := l4IpPrefixKeyString("2001:db8:1234:5600::", 56)
	wantOtherKey := l4IpPrefixKeyString("2001:db8:1234:5700::", 56)

	require.Equal(t, uint64(2), snap.prefix[wantSameKey],
		"two v6 IPs in the same /56 should collapse to one counter at 2")
	require.Equal(t, uint64(1), snap.prefix[wantOtherKey])

	// Every prefix row for v6 must use /56.
	for k := range snap.prefix {
		_, plen, ok := splitPrefixKey(k)
		require.True(t, ok)
		require.Equal(t, uint8(56), plen, "IPv6 input must use /56")
	}
}

func TestRecordL4Ip_IpSniOverflowPerIp(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(1000))
	a.cfg.l4SniMaxKeys = 1000

	const ip = "192.0.2.100"
	// Push the same IP with 35 distinct SNIs. The first maxSnisPerIp=32
	// land as their own (IP, SNI, outcome) keys; the remaining 3 fold
	// into the per-IP overflow sentinel.
	for i := 0; i < 35; i++ {
		sni := fmt.Sprintf("host%d.example.com", i)
		a.RecordL4Ip(ip, sni)
	}

	snap := a.l4IpSnapshot()

	distinctSnis := 0
	var overflowCount uint64
	for k, c := range snap.ipSni {
		gotIp, sni, outcome, ok := splitIpSniKey(k)
		require.True(t, ok)
		require.Equal(t, ip, gotIp)
		require.Equal(t, L4IpOutcomeAllowed, outcome)
		if sni == L4IpOverflowSNI {
			overflowCount += c
			continue
		}
		distinctSnis++
	}

	require.Equal(t, maxSnisPerIp, distinctSnis,
		"first maxSnisPerIp SNIs should land as their own keys")
	require.Equal(t, uint64(35-maxSnisPerIp), overflowCount,
		"connections past the per-IP cap must fold into the per-IP overflow sentinel")
}

func TestRecordL4Ip_IpSniOutcomeAlwaysAllowed(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(100))
	a.cfg.l4SniMaxKeys = 100

	a.RecordL4Ip("10.0.0.1", "x.example.com")
	a.RecordL4Ip("10.0.0.2", "y.example.com")

	snap := a.l4IpSnapshot()
	for k := range snap.ipSni {
		_, _, outcome, ok := splitIpSniKey(k)
		require.True(t, ok)
		require.Equal(t, "allowed", outcome,
			"pre-Phase-9 every row must carry outcome=allowed")
	}
}

func TestRecordL4Ip_EmptySNICollapsesToSentinel(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(100))
	a.cfg.l4SniMaxKeys = 100

	a.RecordL4Ip("10.0.0.1", "")

	snap := a.l4IpSnapshot()
	for k := range snap.ipSni {
		_, sni, _, ok := splitIpSniKey(k)
		require.True(t, ok)
		require.Equal(t, L4SniEmptySNI, sni,
			"empty SNI should collapse to the L4 SNI empty sentinel")
	}
}

func TestRecordL4Ip_ConcurrentNoRace(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret", l4IpEnabled(10_000))
	a.cfg.l4SniMaxKeys = 10_000

	const goroutines = 50
	const perGoroutine = 1000
	const total = goroutines * perGoroutine

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", g%256)
			for i := 0; i < perGoroutine; i++ {
				a.RecordL4Ip(ip, "x.example.com")
			}
		}(g)
	}
	wg.Wait()

	snap := a.l4IpSnapshot()
	var sum uint64
	for _, r := range snap.topkRows {
		sum += r.Count
	}
	require.Equal(t, uint64(total), sum,
		"TopK Count sum must match total RecordL4Ip calls under concurrency")
}

func TestEncodeL4IpTopkRow_JSONShape(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	require.NoError(t, encodeL4IpTopkRow(gz, 42, 33_333_333, "10.0.0.1", 999))
	require.NoError(t, gz.Close())

	row := decodeOne(t, &buf)
	require.Equal(t, "l4_ip_topk", row["_type"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, "10.0.0.1", row["ip"])
	require.Equal(t, float64(999), row["connection_count"])
	require.NotEmpty(t, row["ts"])
}

func TestEncodeL4IpUniquesRawRow_JSONShape(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	require.NoError(t, encodeL4IpUniquesRawRow(gz, 42, 33_333_333, "203.0.113.99"))
	require.NoError(t, gz.Close())

	row := decodeOne(t, &buf)
	require.Equal(t, "l4_ip_uniques_raw", row["_type"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, "203.0.113.99", row["ip"])
	require.NotEmpty(t, row["ts"])
}

func TestEncodeL4IpPrefixRow_JSONShape(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	require.NoError(t, encodeL4IpPrefixRow(gz, 42, 33_333_333, "203.0.113.0", 24, 17))
	require.NoError(t, gz.Close())

	row := decodeOne(t, &buf)
	require.Equal(t, "l4_ip_prefix", row["_type"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, "203.0.113.0", row["prefix"])
	require.Equal(t, float64(24), row["prefix_len"])
	require.Equal(t, float64(17), row["connection_count"])
}

func TestEncodeL4IpSniRow_JSONShape(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	require.NoError(t, encodeL4IpSniRow(gz, 42, 33_333_333, "10.0.0.1", "example.com", "allowed", 5))
	require.NoError(t, gz.Close())

	row := decodeOne(t, &buf)
	require.Equal(t, "l4_ip_sni", row["_type"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, "10.0.0.1", row["ip"])
	require.Equal(t, "example.com", row["sni"])
	require.Equal(t, "allowed", row["outcome"])
	require.Equal(t, float64(5), row["connection_count"])
}

func TestFlushOnce_ShipsAllFourIpRowKinds(t *testing.T) {
	srv, captured := captureServer(t, 204)
	defer srv.Close()

	a := newTestApp(t, srv.URL, "k", l4IpEnabled(100))
	a.cfg.l4SniMaxKeys = 100

	a.RecordL4Ip("203.0.113.1", "a.example.com")
	a.RecordL4Ip("203.0.113.2", "b.example.com")
	a.RecordL4Ip("2001:db8::1", "c.example.com")

	a.flushOnce(a.cfg.maxRetries)

	posts := captured()
	require.Len(t, posts, 1)

	kinds := map[string]int{}
	for _, r := range posts[0].rows {
		if t, ok := r["_type"].(string); ok {
			kinds[t]++
		}
	}
	// l4_sni rides via RecordL4Sni — RecordL4Ip doesn't trigger it
	// directly in this test (the L4Handler calls both; we exercise
	// only RecordL4Ip here).
	require.Greater(t, kinds["l4_ip_topk"], 0, "expected at least one l4_ip_topk row")
	require.Greater(t, kinds["l4_ip_prefix"], 0)
	require.Greater(t, kinds["l4_ip_sni"], 0)
	// l4_ip_uniques_raw is sampled at 1/16 — may or may not fire for
	// any individual input; we don't assert on it here.
}

func TestFlushOnce_RetryParameterUnchangedByPhase2(t *testing.T) {
	// Regression pin: extending encodeBatch's signature didn't break
	// the retry path's row-count accounting (used for the dropped
	// metric).
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(503)
	}))
	defer srv.Close()

	a := newTestApp(t, srv.URL, "k", l4IpEnabled(100), func(a *StatsApp) {
		a.Ingest.MaxRetries = 1
	})
	a.cfg.l4SniMaxKeys = 100
	a.cfg.maxRetries = 1

	a.RecordL4Ip("10.0.0.1", "x.example.com")
	a.flushOnce(a.cfg.maxRetries)
	require.GreaterOrEqual(t, atomic.LoadInt32(&attempts), int32(2),
		"503 should trigger at least one retry")
	require.Greater(t, a.Dropped(), uint64(0))
}

// decodeOne reads a single NDJSON line from a gzipped buffer.
func decodeOne(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	gz, err := gzip.NewReader(buf)
	require.NoError(t, err)
	defer gz.Close()
	scan := bufio.NewScanner(gz)
	require.True(t, scan.Scan(), "expected one NDJSON line")
	var row map[string]any
	require.NoError(t, json.Unmarshal(scan.Bytes(), &row))
	return row
}
