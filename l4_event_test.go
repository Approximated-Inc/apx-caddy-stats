package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordL4Sni_DisabledWhenCapZero(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret")
	// cap defaults to 0 (no L4SniMaxKeys in IngestConfig)

	for i := 0; i < 100; i++ {
		a.RecordL4Sni("example.com")
	}

	rows := a.drainL4SniRows()
	require.Nil(t, rows, "expected no rows when L4 SNI tracking disabled")
}

func TestRecordL4Sni_AccumulatesExistingKey(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L4SniMaxKeys = 100 })
	a.cfg.l4SniMaxKeys = 100

	for i := 0; i < 10; i++ {
		a.RecordL4Sni("example.com")
	}

	rows := a.drainL4SniRows()
	require.Len(t, rows, 1)
	for k, c := range rows {
		require.Equal(t, "example.com", k.SNI)
		require.Equal(t, uint64(10), c.ConnectionCount)
	}
}

func TestRecordL4Sni_OverflowSentinelOnCap(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L4SniMaxKeys = 2 })
	a.cfg.l4SniMaxKeys = 2

	// Fill the two slots, each with >1 count so they survive the filter.
	a.RecordL4Sni("a.example.com")
	a.RecordL4Sni("a.example.com")
	a.RecordL4Sni("b.example.com")
	a.RecordL4Sni("b.example.com")

	// Three more distinct SNIs — all should roll into __overflow__.
	a.RecordL4Sni("c.example.com")
	a.RecordL4Sni("d.example.com")
	a.RecordL4Sni("e.example.com")

	rows := a.drainL4SniRows()

	counts := make(map[string]uint64)
	for k, c := range rows {
		counts[k.SNI] = c.ConnectionCount
	}

	require.Equal(t, uint64(2), counts["a.example.com"])
	require.Equal(t, uint64(2), counts["b.example.com"])
	require.Equal(t, uint64(3), counts[L4SniOverflowSNI])
	// c/d/e shouldn't appear as their own keys — they overflowed.
	require.NotContains(t, counts, "c.example.com")
	require.NotContains(t, counts, "d.example.com")
	require.NotContains(t, counts, "e.example.com")
}

func TestDrainL4SniRows_FiltersSingleOccurrence(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L4SniMaxKeys = 100 })
	a.cfg.l4SniMaxKeys = 100

	a.RecordL4Sni("once.example.com") // count=1 → filtered
	a.RecordL4Sni("twice.example.com")
	a.RecordL4Sni("twice.example.com") // count=2 → kept

	rows := a.drainL4SniRows()

	snis := make(map[string]bool)
	for k := range rows {
		snis[k.SNI] = true
	}

	require.False(t, snis["once.example.com"], "count=1 row must be filtered")
	require.True(t, snis["twice.example.com"], "count=2 row must be kept")
}

func TestDrainL4SniRows_OverflowSentinelExemptFromFilter(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L4SniMaxKeys = 1 })
	a.cfg.l4SniMaxKeys = 1

	// Fill the one slot — count=1 would normally get filtered.
	a.RecordL4Sni("kept.example.com")
	a.RecordL4Sni("kept.example.com")
	// One overflow — sentinel count=1 should survive the filter.
	a.RecordL4Sni("dropped.example.com")

	rows := a.drainL4SniRows()

	counts := make(map[string]uint64)
	for k, c := range rows {
		counts[k.SNI] = c.ConnectionCount
	}

	require.Equal(t, uint64(2), counts["kept.example.com"])
	require.Equal(t, uint64(1), counts[L4SniOverflowSNI],
		"overflow sentinel must survive the count<=1 filter")
}

func TestRecordL4Sni_EmptySNICollapsesToSentinel(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L4SniMaxKeys = 100 })
	a.cfg.l4SniMaxKeys = 100

	a.RecordL4Sni("")
	a.RecordL4Sni("")

	rows := a.drainL4SniRows()

	snis := make(map[string]uint64)
	for k, c := range rows {
		snis[k.SNI] = c.ConnectionCount
	}
	require.Equal(t, uint64(2), snis[L4SniEmptySNI])
}

func TestDrainL4SniRows_EmptyAfterDrain(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L4SniMaxKeys = 100 })
	a.cfg.l4SniMaxKeys = 100

	a.RecordL4Sni("example.com")
	a.RecordL4Sni("example.com")
	_ = a.drainL4SniRows()

	rows := a.drainL4SniRows()
	require.Nil(t, rows, "drain must leave the map empty")
}

func TestEncodeL4SniRow_JSONShape(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	err := encodeL4SniRow(gz, 42, L4SniKey{TsUnixMin: 33_333_333, SNI: "example.com"}, &l4SniCounter{ConnectionCount: 17})
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	gzr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gzr.Close()

	var line []byte
	line, err = readAll(gzr)
	require.NoError(t, err)

	var row map[string]any
	require.NoError(t, json.Unmarshal(line[:len(line)-1], &row)) // strip trailing \n

	require.Equal(t, "l4_sni", row["_type"])
	require.Equal(t, "example.com", row["sni"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, float64(17), row["connection_count"])
	require.NotEmpty(t, row["ts"], "ts should be an RFC3339 string")
}

func readAll(r *gzip.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, 256)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}
