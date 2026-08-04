package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The l7_httpversion encoder is retained as a dormant escape hatch (the L7
// aggregate recorders no longer run — see E.3). This test keeps the wire
// format covered so the dormant encoder stays correct.
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
