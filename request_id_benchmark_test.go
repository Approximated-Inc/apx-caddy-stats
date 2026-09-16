package apxstats

import (
	"compress/gzip"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
)

func BenchmarkRequestUUID(b *testing.B) {
	// PrepareRequest is included in both fresh-request cases so their
	// difference isolates generating and reading the lazy UUID. Neither
	// case includes any network traffic.
	for _, generate := range []bool{false, true} {
		name := "prepare_only"
		if generate {
			name = "prepare_and_generate"
		}
		b.Run(name, func(b *testing.B) {
			r := httptest.NewRequest("GET", "https://customer.example/", nil)
			w := httptest.NewRecorder()
			server := &caddyhttp.Server{}
			b.ReportAllocs()
			for b.Loop() {
				repl := caddy.NewReplacer()
				_ = caddyhttp.PrepareRequest(r, repl, w, server)
				if generate {
					_, _ = repl.Get("http.request.uuid")
				}
			}
		})
	}
	b.Run("cached_read", func(b *testing.B) {
		repl := caddy.NewReplacer()
		_ = caddyhttp.PrepareRequest(httptest.NewRequest("GET", "https://customer.example/", nil), repl, httptest.NewRecorder(), &caddyhttp.Server{})
		_, _ = repl.Get("http.request.uuid")
		b.ReportAllocs()
		for b.Loop() {
			_, _ = repl.Get("http.request.uuid")
		}
	})
}

func BenchmarkRequestEventEncodingV2(b *testing.B) {
	row := requestEventRow{
		TsUnixSec: 1_700_000_000, TsUnixMs: 1_700_000_000_123,
		VhostID: 100, ClientIP: "203.0.113.7", ForwardedIP: "::",
		Method: "GET", Path: "/api/users/42", PathBucket: "/api/users/*",
		Status: 200, HTTPVersion: "HTTP/2.0", UA: "curl/8.0", Origin: "upstream",
		BytesIn: 512, BytesOut: 4096, DurationUs: 12345, SampleRate: 1,
		MachineID: "machine-abc", MachineSeq: 99, Disposition: dispServed, V2: true,
	}
	// UUIDs are prepared outside the timed region to isolate encoding.
	// The corpus exceeds gzip's history window, avoiding unrealistically
	// cheap compression from repeating one ID on every row.
	ids := make([]string, 1024)
	for i := range ids {
		ids[i] = uuid.NewString()
	}
	for _, withID := range []bool{false, true} {
		name := "empty_id"
		if withID {
			name = "unique_id"
		}
		b.Run(name, func(b *testing.B) {
			gz := gzip.NewWriter(io.Discard)
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if withID {
					row.RequestID = ids[i%len(ids)]
					i++
				}
				if err := encodeRequestEventRow(gz, 42, row); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if err := gz.Close(); err != nil {
				b.Fatal(err)
			}
		})
	}
}
