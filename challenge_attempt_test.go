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

func TestRecordChallengeAttempt_OwnsRetainedKeyStrings(t *testing.T) {
	// The challenge map is a long-lived buffer (drained per flush window).
	// Its key strings arrive as slices of request-owned backings: vhost is
	// SplitHostPort(r.Host) (and r.Host can itself be a slice of the full
	// request line for absolute-form URIs), outcome comes from another
	// module's request var. Retaining those slices would pin the parent
	// allocations for the whole window — the map must own its key strings.
	a := newTestApp(t, "http://unused", "secret")
	vhostBacking := "example.com" + strings.Repeat("h", 1<<20)
	ipBacking := "203.0.113.7" + strings.Repeat("i", 1<<20)
	outcomeBacking := "issued" + strings.Repeat("o", 1<<20)
	key := challengeAttemptKey{
		vhost:   vhostBacking[:11],
		ip:      ipBacking[:11],
		outcome: outcomeBacking[:6],
	}
	a.RecordChallengeAttempt(key)
	a.RecordChallengeAttempt(key) // increment path must not re-retain

	a.challengeMu.Lock()
	defer a.challengeMu.Unlock()
	require.Len(t, a.challengeMap, 1)
	for k, n := range a.challengeMap {
		require.Equal(t, uint64(2), n)
		require.Equal(t, "example.com", k.vhost)
		require.Equal(t, "203.0.113.7", k.ip)
		require.Equal(t, "issued", k.outcome)
		if unsafe.StringData(k.vhost) == unsafe.StringData(vhostBacking) {
			t.Error("stored vhost key shares the caller's backing array; want an owned clone")
		}
		if unsafe.StringData(k.ip) == unsafe.StringData(ipBacking) {
			t.Error("stored ip key shares the caller's backing array; want an owned clone")
		}
		if unsafe.StringData(k.outcome) == unsafe.StringData(outcomeBacking) {
			t.Error("stored outcome key shares the caller's backing array; want an owned clone")
		}
	}
}

func TestRecordChallengeAttempt_MergesPerKey(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret")

	// Same (vhost, ip, outcome) several times → one merged row.
	for i := 0; i < 3; i++ {
		a.RecordChallengeAttempt(challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "issued"})
	}
	// Same vhost+ip, different outcome → distinct row.
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "passed"})
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "passed"})
	// Different ip → distinct row.
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "example.com", ip: "198.51.100.1", outcome: "failed"})
	// Different vhost → distinct row.
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "other.com", ip: "203.0.113.7", outcome: "passed_recently"})

	snap := a.challengeSnapshot()
	require.Len(t, snap, 4, "distinct (vhost, ip, outcome) tuples are distinct rows")
	require.Equal(t, uint64(3), snap[challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "issued"}])
	require.Equal(t, uint64(2), snap[challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "passed"}])
	require.Equal(t, uint64(1), snap[challengeAttemptKey{vhost: "example.com", ip: "198.51.100.1", outcome: "failed"}])
	require.Equal(t, uint64(1), snap[challengeAttemptKey{vhost: "other.com", ip: "203.0.113.7", outcome: "passed_recently"}])
}

func TestChallengeSnapshot_EmptyAfterDrain(t *testing.T) {
	a := newTestApp(t, "http://unused", "secret")

	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "issued"})
	_ = a.challengeSnapshot()

	require.Nil(t, a.challengeSnapshot(), "drain must leave the map empty")
}

func TestChallengeSnapshot_NilMapNoOp(t *testing.T) {
	// A zero-valued StatsApp (challengeMap nil) must not panic on record
	// and must drain to nil.
	a := &StatsApp{}
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "issued"})
	require.Nil(t, a.challengeSnapshot())
}

func TestEncodeChallengeAttemptRow_JSONShape(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	k := challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "issued"}
	err := encodeChallengeAttemptRow(gz, 42, 33_333_333, k, 17)
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
	require.Equal(t, `{"_type":"challenge_attempt"`, line[:len(`{"_type":"challenge_attempt"`)],
		"_type must be the first JSON key")

	var row map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &row))
	require.Equal(t, "challenge_attempt", row["_type"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, "example.com", row["vhost"])
	require.Equal(t, "203.0.113.7", row["ip"])
	require.Equal(t, "issued", row["outcome"])
	require.Equal(t, float64(17), row["attempt_count"])
	require.NotEmpty(t, row["ts"], "ts should be an RFC3339 string")
	// vhost_id must NOT appear — challenge rows key by Host, not vhost_id.
	_, hasVhostID := row["vhost_id"]
	require.False(t, hasVhostID, "challenge_attempt rows must not carry vhost_id")
}

// TestEncodeBatch_IncludesChallengeAttemptRows exercises the encodeBatch
// loop end-to-end via the flush path: a recorded attempt must appear as a
// challenge_attempt row in the shipped NDJSON.
func TestEncodeBatch_IncludesChallengeAttemptRows(t *testing.T) {
	srv, captured := captureServer(t, 200)
	defer srv.Close()

	a := newTestApp(t, srv.URL, "secret")
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "issued"})
	a.RecordChallengeAttempt(challengeAttemptKey{vhost: "example.com", ip: "203.0.113.7", outcome: "issued"})

	a.flushOnce(0)

	posts := captured()
	require.Len(t, posts, 1)
	var found map[string]any
	for _, p := range posts {
		for _, row := range p.rows {
			if row["_type"] == "challenge_attempt" {
				found = row
			}
		}
	}
	require.NotNil(t, found, "expected a challenge_attempt row in the batch")
	require.Equal(t, "example.com", found["vhost"])
	require.Equal(t, "203.0.113.7", found["ip"])
	require.Equal(t, "issued", found["outcome"])
	require.Equal(t, float64(2), found["attempt_count"])
	require.Equal(t, float64(42), found["proxy_server_id"])
}
