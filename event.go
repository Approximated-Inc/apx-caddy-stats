package apxstats

import (
	"strconv"
	"time"
)

// Origin classifies which side of the proxy generated the response.
// Mirrors the Elixir-side `origin` LowCardinality(String) column.
const (
	OriginUpstream          = "upstream"            // upstream returned and Caddy passed it through
	OriginCluster           = "cluster"             // Caddy generated the response (no upstream attempted)
	OriginClusterProxyError = "cluster_proxy_error" // upstream attempted, Caddy synthesized the final response
)

// Key is the natural identity of an aggregated counter row. Every field
// must be comparable so the type works as a Go map key. The minute-aligned
// timestamp is the bucket boundary; ts is the START of the minute.
//
// `proxy_server_id` is global per Caddy process (set on StatsApp at
// provision) so it's not part of the key — there's exactly one value.
type Key struct {
	TsUnixMin uint32 // unix minute, fits 2106
	VhostID   uint32
	Method    string // "GET" / "POST" / etc — kept as string; cardinality is small
	Status    uint16 // full HTTP status (200, 404, 502, …)
	Origin    string // OriginUpstream | OriginCluster | OriginClusterProxyError
	Country   string // ISO 3166 alpha-2, "" if unknown
	ASN       uint32 // 0 if unknown
}

// uniqueKey identifies a per-(vhost, minute) set of hashed client
// identifiers. Coarser than Key — uniques are aggregated only by time
// bucket and vhost, not by method/status/origin/country/asn — because
// "unique clients" is a single global count per vhost-minute.
type uniqueKey struct {
	TsUnixMin uint32
	VhostID   uint32
}

// Counter holds the aggregated values for one Key. All fields are summed
// element-wise across requests with the same Key.
//
// Counter is mutated via atomic adds (see app.go's hot path) so the
// increment path is lock-free once the entry exists in the map. Adding
// new entries still requires a mutex, but most requests hit existing keys.
type Counter struct {
	RequestCount  uint64
	BytesIn       uint64
	BytesOut      uint64
	DurationUsSum uint64
	LatBuckets    [HistogramBuckets]uint64
}

// row is the JSON wire form. Sparse on histogram fields — buckets with
// zero counts are omitted to keep batch size down. Matches the contract
// in lib/approximated_web/controllers/analytics_ingest_controller.ex.
type row struct {
	Ts            string `json:"ts"`
	ProxyServerID uint32 `json:"proxy_server_id"`
	VhostID       uint32 `json:"vhost_id"`
	Method        string `json:"method"`
	Status        uint16 `json:"status"`
	Origin        string `json:"origin"`
	Country       string `json:"country"`
	ASN           uint32 `json:"asn"`
	RequestCount  uint64 `json:"request_count"`
	BytesIn       uint64 `json:"bytes_in"`
	BytesOut      uint64 `json:"bytes_out"`
	DurationUsSum uint64 `json:"duration_us_sum"`
	// Histogram buckets get serialized inline by encodeRow — see app.go.
}

// formatTs renders a Unix-minute as RFC3339 UTC, minute-aligned. The
// app-side controller passes the result through DateTime.from_iso8601/1
// so any RFC3339 string with explicit offset works; we always emit "Z".
func formatTs(unixMin uint32) string {
	return time.Unix(int64(unixMin)*60, 0).UTC().Format(time.RFC3339)
}

// histKey returns the JSON key for histogram bucket i (0..15), e.g.
// "lat_b07". Pre-computed at package init for zero-alloc emission.
func histKey(i int) string { return histKeyTable[i] }

var histKeyTable = func() [HistogramBuckets]string {
	var out [HistogramBuckets]string
	for i := range out {
		out[i] = "lat_b" + leftPadInt(i, 2)
	}
	return out
}()

func leftPadInt(n, width int) string {
	s := strconv.Itoa(n)
	for len(s) < width {
		s = "0" + s
	}
	return s
}
