package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeRequestEventRow_ExactNDJSON(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	row := requestEventRow{
		TsUnixSec:   1_700_000_000,
		VhostID:     100,
		ClientIP:    "203.0.113.7",
		ForwardedIP: "198.51.100.9",
		FrontProxy:  "cloudflare",
		Method:      "GET",
		Path:        "/api/users/42",
		PathBucket:  "/api/users/*",
		Status:      200,
		HTTPVersion: "HTTP/2.0",
		UA:          "curl/8.0",
		Origin:      "https://example.com",
		BytesIn:     512,
		BytesOut:    4096,
		DurationUs:  12345,
		SampleRate:  1,
	}
	require.NoError(t, encodeRequestEventRow(gz, 42, row))
	require.NoError(t, gz.Close())

	gzr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gzr.Close()

	line, err := readAll(gzr)
	require.NoError(t, err)

	// Exact byte-for-byte line (field order is part of the Phoenix contract).
	// ts is second-precision RFC3339; NO country/asn/asn_org on the wire.
	want := `{"_type":"request_event","ts":"2023-11-14T22:13:20Z","proxy_server_id":42,"vhost_id":100,"client_ip":"203.0.113.7","forwarded_ip":"198.51.100.9","front_proxy":"cloudflare","method":"GET","path":"/api/users/42","path_bucket":"/api/users/*","status":200,"http_version":"HTTP/2.0","ua":"curl/8.0","origin":"https://example.com","bytes_in":512,"bytes_out":4096,"duration_us":12345,"sample_rate":1}` + "\n"
	require.Equal(t, want, string(line))

	var got map[string]any
	require.NoError(t, json.Unmarshal(line[:len(line)-1], &got))
	require.Equal(t, "request_event", got["_type"])
	require.Equal(t, float64(42), got["proxy_server_id"])
	require.Equal(t, float64(100), got["vhost_id"])
	require.Equal(t, float64(200), got["status"])
	require.Equal(t, float64(1), got["sample_rate"])
	// country/asn/asn_org must be absent — Phoenix fills those at ingest.
	_, hasCountry := got["country"]
	require.False(t, hasCountry)
	_, hasASN := got["asn"]
	require.False(t, hasASN)
}

func TestEncodeRequestEventRow_EscapesStrings(t *testing.T) {
	// path and ua carry arbitrary bytes (quotes, control chars), so they must
	// be JSON-escaped via writeString like the other string fields.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	row := requestEventRow{
		TsUnixSec:  1_700_000_000,
		VhostID:    7,
		Path:       "/a\"b\x01c",
		UA:         "bad\\agent\"x",
		Status:     404,
		SampleRate: 1,
	}
	require.NoError(t, encodeRequestEventRow(gz, 1, row))
	require.NoError(t, gz.Close())

	gzr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gzr.Close()
	line, err := readAll(gzr)
	require.NoError(t, err)

	// Must be valid JSON (escaping correct) and round-trip the raw bytes.
	var got map[string]any
	require.NoError(t, json.Unmarshal(line[:len(line)-1], &got))
	require.Equal(t, "/a\"b\x01c", got["path"])
	require.Equal(t, "bad\\agent\"x", got["ua"])
}
