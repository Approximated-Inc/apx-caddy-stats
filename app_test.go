package apxstats

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestApp builds a StatsApp with a mock HTTP client pointing at the
// given test server. It bypasses Caddy's Provision/Start lifecycle
// since those need a real Caddy context.
func newTestApp(t *testing.T, ingestURL, secret string, opts ...func(*StatsApp)) *StatsApp {
	t.Helper()
	a := &StatsApp{
		ProxyServerIDValue: 42,
		Ingest: &IngestConfig{
			URL:             ingestURL,
			FlushIntervalMs: 50,
			MaxBufferRows:   1000,
			MaxRetries:      0,
			TimeoutMs:       2000,
		},
	}
	for _, opt := range opts {
		opt(a)
	}
	a.secret = secret
	a.cfg = ingestRuntime{
		url:             a.Ingest.URL,
		authHeader:      "apx-key",
		flushInterval:   time.Duration(a.Ingest.FlushIntervalMs) * time.Millisecond,
		maxBuffer:       a.Ingest.MaxBufferRows,
		maxUniqueHashes: intDefault(a.Ingest.MaxUniqueHashes, 500_000),
		maxRetries:      a.Ingest.MaxRetries,
		l4SniMaxKeys:    a.Ingest.L4SniMaxKeys,
	}
	a.client = &http.Client{Timeout: 2 * time.Second}
	for i := range a.shards {
		a.shards[i] = &counterShard{
			counters: make(map[Key]*Counter),
			uniques:  make(map[uniqueKey]map[uint64]struct{}),
		}
	}
	a.l4SniMap = make(map[L4SniKey]*l4SniCounter)
	a.stopCh = make(chan struct{})
	return a
}

type capturedPost struct {
	headers http.Header
	rows    []map[string]any
}

// captureServer returns a server that decodes gzipped NDJSON request
// bodies into row maps and stores them for assertion.
func captureServer(t *testing.T, status int) (*httptest.Server, func() []capturedPost) {
	t.Helper()
	var (
		mu       sync.Mutex
		captured []capturedPost
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var rows []map[string]any
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(bytes.NewReader(raw))
			require.NoError(t, err)
			scan := bufio.NewScanner(gz)
			scan.Buffer(make([]byte, 1<<20), 1<<20)
			for scan.Scan() {
				var m map[string]any
				require.NoError(t, json.Unmarshal(scan.Bytes(), &m))
				rows = append(rows, m)
			}
			require.NoError(t, scan.Err())
		}
		mu.Lock()
		captured = append(captured, capturedPost{headers: r.Header.Clone(), rows: rows})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	return srv, func() []capturedPost {
		mu.Lock()
		defer mu.Unlock()
		out := make([]capturedPost, len(captured))
		copy(out, captured)
		return out
	}
}

// TestRecord_ConcurrentWithFlush is the regression pin for the
// pre-fix race where Record released the mutex before doing per-field
// atomic.Add and flushOnce released the mutex before encoding. Counter
// updates that landed between flush's swap and flush's encode were
// silently dropped.
//
// We launch N goroutines hammering Record on the same key while a flush
// loop snapshots in a tight loop. The total request_count seen across
// all flushes plus what's left in the live map must exactly equal N.
// `go test -race` would also flag the bug independently.
func TestRecord_ConcurrentWithFlush(t *testing.T) {
	srv, captured := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k", func(a *StatsApp) {
		a.Ingest.MaxBufferRows = 100
	})

	const total = 50_000
	k := Key{VhostID: 1, Method: "GET", Status: 200, Origin: OriginUpstream}

	stop := make(chan struct{})
	flushDone := make(chan struct{})

	go func() {
		defer close(flushDone)
		for {
			select {
			case <-stop:
				return
			default:
				a.flushOnce(a.cfg.maxRetries)
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(total)
	for i := 0; i < total; i++ {
		go func() {
			defer wg.Done()
			a.Record(k, CounterDelta{LatBucket: 0})
		}()
	}
	wg.Wait()
	close(stop)
	<-flushDone

	// Drain whatever's left in the live map.
	a.flushOnce(a.cfg.maxRetries)

	var seen uint64
	for _, post := range captured() {
		for _, row := range post.rows {
			if row["vhost_id"] == float64(1) {
				seen += uint64(row["request_count"].(float64))
			}
		}
	}

	require.Equal(t, uint64(total), seen,
		"request_count across all flushes must equal total Records issued (no drops between swap+encode)")
}

func TestRecord_DedupesIdenticalKeys(t *testing.T) {
	srv, _ := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k")

	k := Key{
		TsUnixMin: 29_485_530,
		VhostID:   100,
		Method:    "GET",
		Status:    200,
		Origin:    OriginUpstream,
		Country:   "US",
		ASN:       13335,
	}

	const N = 1000
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			a.Record(k, CounterDelta{BytesIn: 100, BytesOut: 200, DurationUs: 5_000, LatBucket: 3})
		}()
	}
	wg.Wait()

	require.Equal(t, 1, a.counterCount(), "all N inserts must collapse to one map entry")
	c, ok := a.counterFor(k)
	require.True(t, ok)
	require.Equal(t, uint64(N), c.RequestCount)
	require.Equal(t, uint64(N*100), c.BytesIn)
	require.Equal(t, uint64(N*200), c.BytesOut)
	require.Equal(t, uint64(N*5_000), c.DurationUsSum)
	require.Equal(t, uint64(N), c.LatBuckets[3])
}

func TestRecord_DistinctKeysGetSeparateRows(t *testing.T) {
	srv, _ := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k")

	a.Record(Key{VhostID: 1, Method: "GET", Status: 200}, CounterDelta{LatBucket: 0})
	a.Record(Key{VhostID: 1, Method: "GET", Status: 200}, CounterDelta{LatBucket: 0})
	a.Record(Key{VhostID: 2, Method: "GET", Status: 200}, CounterDelta{LatBucket: 0})
	a.Record(Key{VhostID: 1, Method: "POST", Status: 200}, CounterDelta{LatBucket: 0})
	a.Record(Key{VhostID: 1, Method: "GET", Status: 500}, CounterDelta{LatBucket: 0})

	require.Equal(t, 4, a.counterCount())
}

func TestRecord_MaxBufferRowsCapDropsNewKeys(t *testing.T) {
	srv, _ := captureServer(t, 204)
	defer srv.Close()
	// MaxBufferRows is the GLOBAL cap. With shardCount shards, each shard
	// gets MaxBufferRows/shardCount. Pick MaxBufferRows = shardCount*3
	// so each shard's cap is 3 and the total cap is shardCount*3. Then
	// insert keys that all land in the same shard (so we can deterministically
	// test the cap behavior) — easiest: same VhostID, Method, Status,
	// vary only an "internal" field we'll spread artificially.
	a := newTestApp(t, srv.URL, "k", func(a *StatsApp) {
		a.Ingest.MaxBufferRows = shardCount * 3
	})

	// Insert 10 distinct keys that all hash to the same shard by sharing
	// the high-cardinality fields. They differ only in ASN which is
	// hashed into the shard selection, so they may scatter. Instead,
	// insert 10 × shardCount keys spread across shards uniformly — at
	// 3 per shard cap, we'll fill exactly 3*shardCount = 30 and drop 0
	// in the symmetric case. The clearer test is to fill ONE shard
	// past its cap. We use VhostID values such that shardForKey lands
	// them in the same shard, picked by trial.
	target := a.shardForKey(Key{VhostID: 0, Method: "GET", Status: 200})

	var inserted int
	v := uint32(0)
	for inserted < 10 && v < 10_000 {
		k := Key{VhostID: v, Method: "GET", Status: 200}
		if a.shardForKey(k) == target {
			a.Record(k, CounterDelta{LatBucket: 0})
			inserted++
		}
		v++
	}

	snap := a.countersSnapshot()
	require.Equal(t, 3, len(snap), "shard cap (3) caps inserts in this shard")
	require.Equal(t, uint64(7), a.Overflow())

	// Existing keys still count.
	for i := 0; i < 5; i++ {
		for k := range snap {
			a.Record(k, CounterDelta{LatBucket: 0})
			break
		}
	}
	var total uint64
	for _, c := range a.countersSnapshot() {
		total += c.RequestCount
	}
	require.GreaterOrEqual(t, total, uint64(8))
}

func TestFlushOnce_PostsGzippedNDJSON(t *testing.T) {
	srv, captured := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "shared-secret")

	a.Record(Key{
		TsUnixMin: 29_485_530,
		VhostID:   100,
		Method:    "GET",
		Status:    200,
		Origin:    OriginUpstream,
		Country:   "US",
		ASN:       13335,
	}, CounterDelta{BytesIn: 1024, BytesOut: 8192, DurationUs: 25_000, LatBucket: 4})

	a.flushOnce(a.cfg.maxRetries)

	posts := captured()
	require.Len(t, posts, 1)
	require.Equal(t, "shared-secret", posts[0].headers.Get("apx-key"))
	require.Equal(t, "gzip", posts[0].headers.Get("Content-Encoding"))
	require.Equal(t, "application/x-ndjson", posts[0].headers.Get("Content-Type"))

	require.Len(t, posts[0].rows, 1)
	row := posts[0].rows[0]
	// `_type` discriminator pins the row kind so the app-side ingest
	// controller dispatches without inferring from shape. Future row
	// kinds ("event", challenge decisions, etc.) extend this set.
	require.Equal(t, "counter", row["_type"])
	require.Equal(t, float64(42), row["proxy_server_id"])
	require.Equal(t, float64(100), row["vhost_id"])
	require.Equal(t, "GET", row["method"])
	require.Equal(t, float64(200), row["status"])
	require.Equal(t, "upstream", row["origin"])
	require.Equal(t, "US", row["country"])
	require.Equal(t, float64(13335), row["asn"])
	require.Equal(t, float64(1), row["request_count"])
	require.Equal(t, float64(1024), row["bytes_in"])
	require.Equal(t, float64(8192), row["bytes_out"])
	require.Equal(t, float64(25_000), row["duration_us_sum"])
	// Sparse: only bucket 4 should be present.
	require.Equal(t, float64(1), row["lat_b04"])
	for i := 0; i < HistogramBuckets; i++ {
		if i == 4 {
			continue
		}
		_, present := row[histKey(i)]
		require.False(t, present, "bucket %s should be omitted (zero count)", histKey(i))
	}
}

func TestFlushOnce_ResetsCountersBetweenFlushes(t *testing.T) {
	srv, captured := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k")

	k := Key{VhostID: 1, Method: "GET", Status: 200, Origin: OriginCluster}
	a.Record(k, CounterDelta{LatBucket: 0})
	a.flushOnce(a.cfg.maxRetries)
	a.flushOnce(a.cfg.maxRetries) // empty, no-op
	a.Record(k, CounterDelta{LatBucket: 0})
	a.Record(k, CounterDelta{LatBucket: 0})
	a.flushOnce(a.cfg.maxRetries)

	posts := captured()
	require.Len(t, posts, 2)
	require.Equal(t, float64(1), posts[0].rows[0]["request_count"])
	require.Equal(t, float64(2), posts[1].rows[0]["request_count"])
}

func TestFlushOnce_RetriesOnTransientError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k", func(a *StatsApp) {
		a.Ingest.MaxRetries = 4
	})

	a.Record(Key{VhostID: 1, Method: "GET", Status: 200}, CounterDelta{LatBucket: 0})
	a.flushOnce(a.cfg.maxRetries)
	require.Equal(t, int32(3), atomic.LoadInt32(&attempts), "should have retried until success")
	require.Equal(t, uint64(0), a.Dropped())
}

func TestFlushOnce_DropsOnPermanent4xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(400) // bad wire format — retry won't help
	}))
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k", func(a *StatsApp) {
		a.Ingest.MaxRetries = 5
	})

	a.Record(Key{VhostID: 1, Method: "GET", Status: 200}, CounterDelta{LatBucket: 0})
	a.flushOnce(a.cfg.maxRetries)
	require.Equal(t, int32(1), atomic.LoadInt32(&attempts), "4xx should not be retried")
	require.Equal(t, uint64(1), a.Dropped())
}

func TestFlushOnce_DropsAfterRetryExhaustion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k", func(a *StatsApp) {
		a.Ingest.MaxRetries = 2
	})

	a.Record(Key{VhostID: 1, Method: "GET", Status: 200}, CounterDelta{LatBucket: 0})
	a.Record(Key{VhostID: 2, Method: "GET", Status: 200}, CounterDelta{LatBucket: 0})
	a.flushOnce(a.cfg.maxRetries)
	require.Equal(t, uint64(2), a.Dropped(), "both rows should be dropped")
}

func TestRecordUnique_DedupesAndShipsArrayRow(t *testing.T) {
	srv, captured := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k")
	a.hashSalt = "test-salt"

	a.RecordUnique(100, 7, 0xAAAA)
	a.RecordUnique(100, 7, 0xBBBB)
	a.RecordUnique(100, 7, 0xAAAA) // duplicate of the first; should dedupe
	a.RecordUnique(100, 8, 0xCCCC) // different vhost; separate row

	a.flushOnce(a.cfg.maxRetries)
	posts := captured()
	require.Len(t, posts, 1)

	// Two rows: vhost 7 has {AAAA, BBBB}, vhost 8 has {CCCC}.
	// Order isn't guaranteed across map iteration; group by vhost_id.
	// Every uniques row also carries _type: "uniques" so the app-side
	// controller can dispatch without inferring from shape.
	byVhost := map[float64]map[string]any{}
	for _, r := range posts[0].rows {
		if _, ok := r["client_hashes"]; !ok {
			continue
		}
		require.Equal(t, "uniques", r["_type"], "uniques rows carry _type discriminator")
		byVhost[r["vhost_id"].(float64)] = r
	}
	require.Len(t, byVhost, 2)

	require.ElementsMatch(t,
		[]uint64{0xAAAA, 0xBBBB},
		hashesAsUint64(byVhost[7]["client_hashes"]),
	)
	require.Equal(t,
		[]uint64{0xCCCC},
		hashesAsUint64(byVhost[8]["client_hashes"]),
	)
}

func TestRecordUnique_CapsTotalHashes(t *testing.T) {
	srv, _ := captureServer(t, 204)
	defer srv.Close()

	// Cap is GLOBAL across shards; per-shard cap = MaxUniqueHashes / shardCount.
	// Pick MaxUniqueHashes = 3 * shardCount so per-shard cap = 3, then drive
	// all inserts into one shard by picking (ts, vhost) values that hash there.
	a := newTestApp(t, srv.URL, "k", func(a *StatsApp) {
		a.Ingest.MaxUniqueHashes = 3 * shardCount
	})
	a.cfg.maxUniqueHashes = 3 * shardCount
	a.hashSalt = "test-salt"

	// Find two (ts, vhost) pairs that land in the same shard.
	targetShard := a.shardForUnique(100, 1)
	var altV uint32
	for v := uint32(2); v < 10_000; v++ {
		if a.shardForUnique(100, v) == targetShard {
			altV = v
			break
		}
	}
	require.NotZero(t, altV, "couldn't find two same-shard vhosts")

	// First three inserts (all in target shard) succeed
	a.RecordUnique(100, 1, 0xA1)
	a.RecordUnique(100, 1, 0xA2)
	a.RecordUnique(100, altV, 0xB1)

	require.Equal(t, uint64(3), a.uniqueHashTotal())
	require.Equal(t, uint64(0), a.uniquesOverflow)

	// Fourth distinct hash in this shard overflows
	a.RecordUnique(100, altV, 0xB2)
	require.Equal(t, uint64(3), a.uniqueHashTotal(), "no new entry past per-shard cap")
	require.Equal(t, uint64(1), a.uniquesOverflow, "overflow counter bumped")

	// Duplicate of an existing hash doesn't bump overflow (idempotent)
	a.RecordUnique(100, 1, 0xA1)
	require.Equal(t, uint64(1), a.uniquesOverflow, "dup is silent, not overflow")

	// Flush resets the running count
	a.flushOnce(a.cfg.maxRetries)
	require.Equal(t, uint64(0), a.uniqueHashTotal())
}

func TestRecordUnique_NoSaltIsNoop(t *testing.T) {
	srv, captured := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k")
	// hashSalt left empty by default — feature is disabled
	require.Empty(t, a.HashSalt())

	a.RecordUnique(100, 7, 0xAAAA)
	require.True(t, a.uniquesEmpty())

	// flush with both maps empty is a no-op (no POST issued)
	a.flushOnce(a.cfg.maxRetries)
	require.Empty(t, captured())
}

func TestRecordUnique_FlushesWithCountersInSameBatch(t *testing.T) {
	srv, captured := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k")
	a.hashSalt = "test-salt"

	a.Record(Key{TsUnixMin: 100, VhostID: 7, Method: "GET", Status: 200, Origin: OriginUpstream},
		CounterDelta{BytesIn: 100, BytesOut: 200})
	a.RecordUnique(100, 7, 0xDEADBEEF)

	a.flushOnce(a.cfg.maxRetries)
	posts := captured()
	require.Len(t, posts, 1)

	// Single batch carries both row kinds. Counter row has request_count;
	// uniques row has client_hashes.
	var counterRows, uniquesRows int
	for _, r := range posts[0].rows {
		if _, ok := r["client_hashes"]; ok {
			uniquesRows++
		} else if _, ok := r["request_count"]; ok {
			counterRows++
		}
	}
	require.Equal(t, 1, counterRows)
	require.Equal(t, 1, uniquesRows)
}

// hashesAsUint64 converts the JSON-decoded `client_hashes` array (a
// []any of float64) into a []uint64 for comparison. JSON numbers fit
// uint64 precision losslessly only up to 2^53, but our test fixtures
// stay well below that.
func hashesAsUint64(v any) []uint64 {
	arr, _ := v.([]any)
	out := make([]uint64, 0, len(arr))
	for _, x := range arr {
		out = append(out, uint64(x.(float64)))
	}
	return out
}

func TestFormatTs_RoundTripsViaIngest(t *testing.T) {
	srv, captured := captureServer(t, 204)
	defer srv.Close()
	a := newTestApp(t, srv.URL, "k")

	now := time.Now().UTC().Truncate(time.Minute)
	unixMin := uint32(now.Unix() / 60)
	a.Record(Key{TsUnixMin: unixMin, VhostID: 1, Method: "GET", Status: 200, Origin: OriginUpstream},
		CounterDelta{LatBucket: 0})
	a.flushOnce(a.cfg.maxRetries)

	posts := captured()
	require.Len(t, posts, 1)
	tsStr, _ := posts[0].rows[0]["ts"].(string)
	parsed, err := time.Parse(time.RFC3339, tsStr)
	require.NoError(t, err)
	require.Equal(t, now.Unix(), parsed.UTC().Unix())
}
