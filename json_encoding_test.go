package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestJSONStringEncoding_StrictUTF8(t *testing.T) {
	t.Parallel()
	var allBytes, controls string
	for i := 0; i < 256; i++ {
		allBytes += string([]byte{byte(i)})
		if i < 0x20 {
			controls += string([]byte{byte(i)})
		}
	}
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"ascii", "sentinel-ASCII/1.0 <>&\x7f", "sentinel-ASCII/1.0 <>&\x7f"},
		{"pinned_reproduction", "a\xffz", "a\ufffdz"},
		{"invalid_bytes", "\xff\xfe\x80\xbf", "\ufffd\ufffd\ufffd\ufffd"},
		{"truncated_two_byte", "end\xc2", "end\ufffd"},
		{"truncated_three_byte", "end\xe2\x82", "end\ufffd\ufffd"},
		{"truncated_four_byte", "end\xf0\x9f\x9a", "end\ufffd\ufffd\ufffd"},
		{"overlong", "\xc0\xaf", "\ufffd\ufffd"},
		{"surrogate", "\xed\xa0\x80", "\ufffd\ufffd\ufffd"},
		{"above_unicode_max", "\xf4\x90\x80\x80", "\ufffd\ufffd\ufffd\ufffd"},
		{"interrupted_sequence", "\xe2(\xa1", "\ufffd(\ufffd"},
		{"mixed_unicode", "café\xff 東京 \xe2\x82 🚀", "café\ufffd 東京 \ufffd\ufffd 🚀"},
		{"valid_unicode", "café 東京 🚀 e\u0301 \ufffd \u2028\u2029", "café 東京 🚀 e\u0301 \ufffd \u2028\u2029"},
		{"controls", controls, controls},
		{"quotes_backslashes", "\"sentinel\\\b\f\n\r\t\x00\"", "\"sentinel\\\b\f\n\r\t\x00\""},
		{"mixed_escaping", "\xff\"<>&\\\n東京\xe2\x82", "\ufffd\"<>&\\\n東京\ufffd\ufffd"},
		{"all_byte_values", allBytes, allBytes[:128] + strings.Repeat("\ufffd", 128)},
	}
	encoders := []struct {
		name   string
		encode func(string) string
	}{
		{"jsonEscape", func(s string) string { return `{"ua":` + jsonEscape(s) + `}` }},
		{"writeString", func(s string) string {
			var b strings.Builder
			b.WriteByte('{')
			writeString(&b, "ua", s)
			b.WriteByte('}')
			return b.String()
		}},
	}
	for _, encoder := range encoders {
		t.Run(encoder.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					encoded := encoder.encode(tc.input)
					// Go's JSON parser accepts invalid UTF-8, so check bytes first.
					require.True(t, utf8.ValidString(encoded),
						"invalid UTF-8; json.Valid=%t; input=%x", json.Valid([]byte(encoded)), tc.input)
					require.True(t, json.Valid([]byte(encoded)))
					var got map[string]string
					require.NoError(t, json.Unmarshal([]byte(encoded), &got))
					require.Equal(t, map[string]string{"ua": tc.want}, got)
					if encoder.name == "writeString" && tc.name == "pinned_reproduction" {
						t.Logf("synthetic_object_base64=%s", base64.StdEncoding.EncodeToString([]byte(encoded)))
					}
				})
			}
		})
	}
}

func TestWriteString_ASCIIFastPath(t *testing.T) {
	var b strings.Builder
	allocs := testing.AllocsPerRun(100, func() {
		b.Reset()
		b.Grow(64)
		writeString(&b, "ua", "sentinel-ASCII/1.0 <>&\x7f")
	})
	require.Equal(t, "\"ua\":\"sentinel-ASCII/1.0 <>&\x7f\"", b.String())
	require.Equal(t, float64(1), allocs, "ASCII must allocate only the builder buffer")
}

func TestEncodeBatch_RequestEventsStrictUTF8(t *testing.T) {
	t.Parallel()
	rows := []requestEventRow{
		{
			TsUnixSec:   1_700_000_000,
			VhostID:     7,
			ClientIP:    "203.0.113.7",
			ForwardedIP: "198.51.100.9",
			FrontProxy:  "none",
			Method:      "GET",
			Path:        "/sentinel/\xff",
			PathBucket:  "/sentinel/\xe2\x82",
			Status:      200,
			HTTPVersion: "HTTP/2.0",
			UA:          "a\xffz",
			Origin:      "upstream",
			BytesIn:     12,
			BytesOut:    34,
			DurationUs:  56,
			SampleRate:  1,
		},
	}
	v2 := rows[0]
	v2.V2 = true
	v2.TsUnixMs = 1_700_000_000_123
	v2.MachineID = "synthetic-machine"
	v2.MachineSeq = 2
	v2.Disposition = dispServed
	v2.Host = "sentinel.invalid"
	v2.UA = "sentinel café\xff \"\\\t\n東京 \xe2\x82 🚀"
	rows = append(rows, v2)

	body, err := encodeBatch(42, 28_333_333, nil, nil, nil, l4IpSnap{}, nil, nil, nil, nil, nil, rows)
	require.NoError(t, err)
	gz, err := gzip.NewReader(bytes.NewReader(body))
	require.NoError(t, err)
	defer gz.Close()
	ndjson, err := io.ReadAll(gz)
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(ndjson, []byte{'\n'}))
	lines := bytes.Split(bytes.TrimSuffix(ndjson, []byte{'\n'}), []byte{'\n'})
	require.Len(t, lines, 2, "embedded newlines must not split request events")
	require.True(t, utf8.Valid(ndjson), "gzip must contain strict UTF-8; first row json.Valid=%t", json.Valid(lines[0]))

	for i, line := range lines {
		require.True(t, utf8.Valid(line))
		require.True(t, json.Valid(line))
		var got map[string]any
		require.NoError(t, json.Unmarshal(line, &got))
		want := map[string]any{
			"_type": "request_event", "ts": "2023-11-14T22:13:20Z",
			"proxy_server_id": float64(42), "vhost_id": float64(7),
			"client_ip": "203.0.113.7", "forwarded_ip": "198.51.100.9",
			"front_proxy": "none", "method": "GET", "path": "/sentinel/\ufffd",
			"path_bucket": "/sentinel/\ufffd\ufffd", "status": float64(200),
			"http_version": "HTTP/2.0", "ua": "a\ufffdz", "origin": "upstream",
			"bytes_in": float64(12), "bytes_out": float64(34),
			"duration_us": float64(56), "sample_rate": float64(1),
		}
		if i == 1 {
			want["ts_ms"] = float64(1_700_000_000_123)
			want["machine_id"] = "synthetic-machine"
			want["machine_seq"] = float64(2)
			want["disposition"] = "served"
			want["host"] = "sentinel.invalid"
			want["ua"] = "sentinel café\ufffd \"\\\t\n東京 \ufffd\ufffd 🚀"
		}
		require.Equal(t, want, got, "row %d", i)
	}
	t.Logf("synthetic_batch_gzip_base64=%s", base64.StdEncoding.EncodeToString(body))
	t.Logf("synthetic_batch_ndjson_base64=%s", base64.StdEncoding.EncodeToString(ndjson))
}
