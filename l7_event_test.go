package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordL7Httpversion_DisabledByDefault(t *testing.T) {
	// newTestApp passes no ingest.l7 block → l7Enabled must be false and
	// RecordL7Httpversion is a no-op (map stays empty).
	a := newTestApp(t, "http://unused", "secret")
	require.False(t, a.cfg.l7Enabled)
	require.Equal(t, L7HttpversionMaxKeysDefault, a.cfg.l7HvMaxKeys)

	for i := 0; i < 100; i++ {
		a.RecordL7Httpversion(100, "2", 2)
	}
	require.Nil(t, a.l7HvSnapshot(), "disabled track must record nothing")
}

func TestRecordL7Httpversion_EnabledViaConfig(t *testing.T) {
	// ingest.l7.enabled=true (no max_keys) → enabled + generous default cap.
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L7 = &L7Config{Enabled: true} })
	require.True(t, a.cfg.l7Enabled)
	require.Equal(t, L7HttpversionMaxKeysDefault, a.cfg.l7HvMaxKeys)
}

func TestRecordL7Httpversion_DisabledViaConfigFalse(t *testing.T) {
	// Explicit enabled:false keeps the track off.
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L7 = &L7Config{Enabled: false} })
	require.False(t, a.cfg.l7Enabled)

	a.RecordL7Httpversion(100, "2", 2)
	require.Nil(t, a.l7HvSnapshot())
}

func TestRecordL7Httpversion_AccumulatesExistingKey(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L7 = &L7Config{Enabled: true} })

	for i := 0; i < 7; i++ {
		a.RecordL7Httpversion(100, "2", 2)
	}
	// A different status bucket is a distinct key.
	a.RecordL7Httpversion(100, "2", 4)

	snap := a.l7HvSnapshot()
	require.Len(t, snap, 2)
	min := timeNowUnixMin()
	c := snap[L7HttpversionKey{TsUnixMin: min, VhostID: 100, HttpVersion: "2", StatusBucket: 2}]
	require.NotNil(t, c)
	require.Equal(t, uint64(7), c.RequestCount)
}

func TestRecordL7Httpversion_CapDropsNewKeysNoSentinel(t *testing.T) {
	// At cap, a new key is DROPPED and counted in l7HvOverflow — NO
	// __overflow__ sentinel row (fingerprint model, not l4_sni). A sentinel
	// http_version would fail the Phoenix whitelist (1.1|2|3|other).
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L7 = &L7Config{Enabled: true, MaxKeys: 2} })
	require.Equal(t, 2, a.cfg.l7HvMaxKeys)

	a.RecordL7Httpversion(1, "2", 2)   // key 1
	a.RecordL7Httpversion(2, "1.1", 4) // key 2 (at cap now)
	a.RecordL7Httpversion(3, "3", 5)   // new key → dropped
	a.RecordL7Httpversion(4, "other", 0)
	// Existing key still increments past cap.
	a.RecordL7Httpversion(1, "2", 2)

	require.Equal(t, uint64(2), a.l7HvOverflow)

	snap := a.l7HvSnapshot()
	require.Len(t, snap, 2, "cap enforced — only 2 keys")
	min := timeNowUnixMin()
	require.Equal(t, uint64(2),
		snap[L7HttpversionKey{TsUnixMin: min, VhostID: 1, HttpVersion: "2", StatusBucket: 2}].RequestCount)
	// No sentinel http_version anywhere.
	for k := range snap {
		require.NotEqual(t, "__overflow__", k.HttpVersion)
	}
}

func TestL7HvSnapshot_ResetsMap(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret",
		func(a *StatsApp) { a.Ingest.L7 = &L7Config{Enabled: true} })

	a.RecordL7Httpversion(100, "2", 2)
	require.NotNil(t, a.l7HvSnapshot())
	require.Nil(t, a.l7HvSnapshot(), "snapshot must leave the map empty")
}

func TestEncodeL7HttpversionRow_ExactNDJSON(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	k := L7HttpversionKey{TsUnixMin: 33_333_333, VhostID: 100, HttpVersion: "2", StatusBucket: 2}
	err := encodeL7HttpversionRow(gz, 42, k, &l7HttpversionCounter{RequestCount: 17})
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	gzr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gzr.Close()

	line, err := readAll(gzr)
	require.NoError(t, err)

	// Exact byte-for-byte line (field order is part of the Phoenix contract).
	want := `{"_type":"l7_httpversion","ts":"2033-05-18T03:33:00Z","proxy_server_id":42,"vhost_id":100,"http_version":"2","status_bucket":2,"request_count":17}` + "\n"
	require.Equal(t, want, string(line))

	// Also assert the decoded shape for good measure.
	var row map[string]any
	require.NoError(t, json.Unmarshal(line[:len(line)-1], &row))
	require.Equal(t, "l7_httpversion", row["_type"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, float64(100), row["vhost_id"])
	require.Equal(t, "2", row["http_version"])
	require.Equal(t, float64(2), row["status_bucket"])
	require.Equal(t, float64(17), row["request_count"])
}
