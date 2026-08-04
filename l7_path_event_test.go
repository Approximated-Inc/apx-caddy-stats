package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeL7PathRow_ExactNDJSON(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	k := L7PathKey{TsUnixMin: 33_333_333, VhostID: 100, PathBucket: "/api/users/*", StatusBucket: 2}
	err := encodeL7PathRow(gz, 42, k, 17)
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	gzr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gzr.Close()

	line, err := readAll(gzr)
	require.NoError(t, err)

	// Exact byte-for-byte line (field order is part of the Phoenix contract).
	want := `{"_type":"l7_path","ts":"2033-05-18T03:33:00Z","proxy_server_id":42,"vhost_id":100,"path_bucket":"/api/users/*","status_bucket":2,"request_count":17}` + "\n"
	require.Equal(t, want, string(line))

	// Also assert the decoded shape for good measure.
	var row map[string]any
	require.NoError(t, json.Unmarshal(line[:len(line)-1], &row))
	require.Equal(t, "l7_path", row["_type"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, float64(100), row["vhost_id"])
	require.Equal(t, "/api/users/*", row["path_bucket"])
	require.Equal(t, float64(2), row["status_bucket"])
	require.Equal(t, float64(17), row["request_count"])
}

func TestEncodeL7PathRow_EscapesPathBucket(t *testing.T) {
	// path_bucket goes through writeString, so a value needing escape (a
	// quote) must be JSON-escaped like the other string fields.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	k := L7PathKey{TsUnixMin: 33_333_333, VhostID: 7, PathBucket: `/a"b`, StatusBucket: 4}
	require.NoError(t, encodeL7PathRow(gz, 1, k, 1))
	require.NoError(t, gz.Close())

	gzr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gzr.Close()
	line, err := readAll(gzr)
	require.NoError(t, err)

	var row map[string]any
	require.NoError(t, json.Unmarshal(line[:len(line)-1], &row))
	require.Equal(t, `/a"b`, row["path_bucket"])
}
