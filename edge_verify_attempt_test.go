package apxstats

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestRecordEdgeVerifyAttempt_OwnsRetainedKeyStrings(t *testing.T) {
	// The Edge Verify map is a long-lived buffer (drained per flush window).
	// Its key strings arrive as slices of request-owned backings: vhost is
	// SplitHostPort(r.Host), path_bucket is derived from r.URL.Path, outcome
	// comes from another module's request var. Retaining those slices would
	// pin the parent allocations for the whole window — the map must own its
	// key strings.
	a := newTestApp(t, "http://unused", "secret")
	vhostBacking := "example.com" + strings.Repeat("h", 1<<20)
	pathBacking := "/checkout" + strings.Repeat("p", 1<<20)
	outcomeBacking := "passed" + strings.Repeat("o", 1<<20)
	key := edgeVerifyAttemptKey{
		vhost:      vhostBacking[:11],
		pathBucket: pathBacking[:9],
		outcome:    outcomeBacking[:6],
	}
	a.RecordEdgeVerifyAttempt(key)
	a.RecordEdgeVerifyAttempt(key) // increment path must not re-retain

	a.edgeVerifyMu.Lock()
	defer a.edgeVerifyMu.Unlock()
	require.Len(t, a.edgeVerifyMap, 1)
	for k, n := range a.edgeVerifyMap {
		require.Equal(t, uint64(2), n)
		require.Equal(t, "example.com", k.vhost)
		require.Equal(t, "/checkout", k.pathBucket)
		require.Equal(t, "passed", k.outcome)
		if unsafe.StringData(k.vhost) == unsafe.StringData(vhostBacking) {
			t.Error("stored vhost key shares the caller's backing array; want an owned clone")
		}
		if unsafe.StringData(k.pathBucket) == unsafe.StringData(pathBacking) {
			t.Error("stored path_bucket key shares the caller's backing array; want an owned clone")
		}
		if unsafe.StringData(k.outcome) == unsafe.StringData(outcomeBacking) {
			t.Error("stored outcome key shares the caller's backing array; want an owned clone")
		}
	}
}

func TestRecordEdgeVerifyAttempt_MergesPerKey(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret")

	// Same (vhost, path_bucket, outcome) several times → one merged row.
	for i := 0; i < 3; i++ {
		a.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "passed"})
	}
	// Same vhost+path, different outcome → distinct row.
	a.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "invalid"})
	a.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "invalid"})
	// Different path_bucket → distinct row.
	a.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/login", outcome: "missing"})
	// Different vhost → distinct row.
	a.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{vhost: "other.com", pathBucket: "/checkout", outcome: "expired"})

	snap := a.edgeVerifySnapshot()
	require.Len(t, snap, 4, "distinct (vhost, path_bucket, outcome) tuples are distinct rows")
	require.Equal(t, uint64(3), snap[edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "passed"}])
	require.Equal(t, uint64(2), snap[edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "invalid"}])
	require.Equal(t, uint64(1), snap[edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/login", outcome: "missing"}])
	require.Equal(t, uint64(1), snap[edgeVerifyAttemptKey{vhost: "other.com", pathBucket: "/checkout", outcome: "expired"}])
}

func TestEdgeVerifySnapshot_EmptyAfterDrain(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret")

	a.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "passed"})
	_ = a.edgeVerifySnapshot()

	require.Nil(t, a.edgeVerifySnapshot(), "drain must leave the map empty")
}

func TestEdgeVerifySnapshot_NilMapNoOp(t *testing.T) {
	// A zero-valued StatsApp (edgeVerifyMap nil) must not panic on record and
	// must drain to nil.
	a := &StatsApp{}
	a.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "passed"})
	require.Nil(t, a.edgeVerifySnapshot())
}

func TestEncodeEdgeVerifyAttemptRow_JSONShape(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	k := edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "passed"}
	err := encodeEdgeVerifyAttemptRow(gz, 42, 33_333_333, k, 17)
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	gzr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gzr.Close()

	raw, err := readAll(gzr)
	require.NoError(t, err)

	// _type MUST be the first key on the wire (Phoenix contract).
	line := string(raw[:len(raw)-1]) // strip trailing \n
	require.True(t, len(line) > 0)
	require.Equal(t, `{"_type":"edge_verify_attempt"`, line[:len(`{"_type":"edge_verify_attempt"`)],
		"_type must be the first JSON key")

	var row map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &row))
	require.Equal(t, "edge_verify_attempt", row["_type"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, "example.com", row["vhost"])
	require.Equal(t, "/checkout", row["path_bucket"])
	require.Equal(t, "passed", row["outcome"])
	require.Equal(t, float64(17), row["attempt_count"])
	require.NotEmpty(t, row["ts"], "ts should be an RFC3339 string")
	// ip must NOT appear — Edge Verify rows key by path_bucket, not ip.
	_, hasIP := row["ip"]
	require.False(t, hasIP, "edge_verify_attempt rows must not carry ip")
	// vhost_id must NOT appear — Edge Verify rows key by Host, not vhost_id.
	_, hasVhostID := row["vhost_id"]
	require.False(t, hasVhostID, "edge_verify_attempt rows must not carry vhost_id")
}

// TestEncodeBatch_IncludesEdgeVerifyAttemptRows exercises the
// encodeBatch loop end-to-end via the flush path: a recorded attempt must
// appear as an edge_verify_attempt row in the shipped NDJSON.
func TestEncodeBatch_IncludesEdgeVerifyAttemptRows(t *testing.T) {
	srv, captured := captureServer(t, 200)
	defer srv.Close()

	a := newTestApp(t, srv.URL, "secret")
	a.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "passed"})
	a.RecordEdgeVerifyAttempt(edgeVerifyAttemptKey{vhost: "example.com", pathBucket: "/checkout", outcome: "passed"})

	a.flushOnce(0)

	posts := captured()
	require.Len(t, posts, 1)
	var found map[string]any
	for _, p := range posts {
		for _, row := range p.rows {
			if row["_type"] == "edge_verify_attempt" {
				found = row
			}
		}
	}
	require.NotNil(t, found, "expected an edge_verify_attempt row in the batch")
	require.Equal(t, "example.com", found["vhost"])
	require.Equal(t, "/checkout", found["path_bucket"])
	require.Equal(t, "passed", found["outcome"])
	require.Equal(t, float64(2), found["attempt_count"])
	require.Equal(t, float64(42), found["proxy_server_id"])
}
