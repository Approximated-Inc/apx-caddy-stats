package apxstats

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// drainMap collapses a drain result into a key->count map for assertions.
func drainMap(rows []l7PathRow) map[L7PathKey]uint64 {
	m := make(map[L7PathKey]uint64, len(rows))
	for _, r := range rows {
		m[r.Key] += r.Count
	}
	return m
}

func TestPerVhostFair_RecordAccumulates(t *testing.T) {
	// TopK is exact for cardinality well under k, so we can assert ==.
	p := newPerVhostFair(64, 16, 0, 0)
	for i := 0; i < 9; i++ {
		p.record(100, "/api/users", 2)
	}
	// A different status bucket is a distinct combined item.
	p.record(100, "/api/users", 4)

	rows, overflow := p.drain(777)
	require.Zero(t, overflow)
	m := drainMap(rows)
	require.Equal(t, uint64(9), m[L7PathKey{TsUnixMin: 777, VhostID: 100, PathBucket: "/api/users", StatusBucket: 2}])
	require.Equal(t, uint64(1), m[L7PathKey{TsUnixMin: 777, VhostID: 100, PathBucket: "/api/users", StatusBucket: 4}])
}

func TestPerVhostFair_DrainStatusBucketZero(t *testing.T) {
	// statusBucket==0 (HTTP code outside 100-599) packs the combined item
	// as path + "\x00" + "\x00", so the item ends in two NULs. drain must
	// split on the FIRST NUL (separator), not the last, or it panics /
	// corrupts the path. This is the regression guard for that bug.
	p := newPerVhostFair(64, 16, 0, 0)

	require.NotPanics(t, func() {
		p.record(100, "/api/users", 0)
	})

	// Same vhost+path, two distinct status buckets (0 and 2) -> two rows.
	p.record(100, "/api/users", 0)
	p.record(100, "/api/users", 2)

	var rows []l7PathRow
	require.NotPanics(t, func() {
		rows, _ = p.drain(555)
	})
	m := drainMap(rows)

	// statusBucket 0 round-trips: path intact (no trailing NUL), status 0.
	require.Equal(t, uint64(2),
		m[L7PathKey{TsUnixMin: 555, VhostID: 100, PathBucket: "/api/users", StatusBucket: 0}])
	// statusBucket 2 is a distinct row.
	require.Equal(t, uint64(1),
		m[L7PathKey{TsUnixMin: 555, VhostID: 100, PathBucket: "/api/users", StatusBucket: 2}])

	// No drained key carries a spurious trailing NUL on its path bucket.
	for k := range m {
		require.False(t, strings.HasSuffix(k.PathBucket, "\x00"),
			"path bucket %q must not retain a trailing NUL", k.PathBucket)
	}
}

func TestPerVhostFair_ShardAssignment(t *testing.T) {
	p := newPerVhostFair(16*4, 8, 0, 0)
	// vhost 19 -> shard 3; vhost 35 -> shard 3.
	p.record(19, "/a", 2)
	p.record(35, "/b", 2)
	// Shard 3 must hold both; no other shard populated.
	for i, sh := range p.shards {
		sh.mu.Lock()
		n := len(sh.vhosts)
		sh.mu.Unlock()
		if i == 3 {
			require.Equal(t, 2, n, "shard 3 should hold both congruent vhosts")
		} else {
			require.Zero(t, n, "shard %d should be empty", i)
		}
	}
}

func TestPerVhostFair_PerShardCapFirstMover(t *testing.T) {
	// trackedVhosts=16 -> perShardN = ceil(16/16) = 1: one vhost per shard.
	p := newPerVhostFair(16, 8, 0, 0)
	require.Equal(t, 1, p.perShardN)

	// vhost 5 -> shard 5 (first mover, admitted).
	p.record(5, "/a", 2)
	// vhost 21 (== 5 mod 16) -> shard 5, at cap -> rejected.
	p.record(21, "/b", 2)
	p.record(21, "/b", 2) // rejected again, overflow increments per call.

	rows, overflow := p.drain(900)
	require.Equal(t, uint64(2), overflow, "two rejected records this window")
	m := drainMap(rows)
	require.Equal(t, uint64(1), m[L7PathKey{TsUnixMin: 900, VhostID: 5, PathBucket: "/a", StatusBucket: 2}])
	// The rejected vhost never appears.
	for k := range m {
		require.NotEqual(t, uint32(21), k.VhostID, "rejected vhost must not be drained")
	}
}

func TestPerVhostFair_DrainStampsAndSplitsAndClears(t *testing.T) {
	p := newPerVhostFair(64, 16, 0, 0)
	p.record(100, "/api/users/*", 5)
	p.record(100, "/healthz", 2)

	rows, overflow := p.drain(123456)
	require.Zero(t, overflow)
	m := drainMap(rows)
	// Stamped drainMin + split combined key back to (path, status).
	require.Contains(t, m, L7PathKey{TsUnixMin: 123456, VhostID: 100, PathBucket: "/api/users/*", StatusBucket: 5})
	require.Contains(t, m, L7PathKey{TsUnixMin: 123456, VhostID: 100, PathBucket: "/healthz", StatusBucket: 2})

	// Second drain with no intervening records: empty + overflow 0 (cleared).
	rows2, overflow2 := p.drain(123457)
	require.Empty(t, rows2)
	require.Zero(t, overflow2)
}

func TestPerVhostFair_DrainClearsOverflow(t *testing.T) {
	p := newPerVhostFair(16, 8, 0, 0) // perShardN = 1
	p.record(5, "/a", 2)
	p.record(21, "/b", 2) // rejected -> overflow 1
	_, overflow := p.drain(1)
	require.Equal(t, uint64(1), overflow)

	// Overflow reset after drain.
	_, overflow2 := p.drain(2)
	require.Zero(t, overflow2)
}

func TestPerVhostFair_ExplicitWidthDepth(t *testing.T) {
	// Explicit width/depth must build sketches with those dims and still
	// record correctly.
	p := newPerVhostFair(64, 16, 256, 4)
	require.Equal(t, 256, p.width)
	require.Equal(t, 4, p.depth)

	p.record(100, "/api", 2)
	sh := p.shards[100%l7ShardCount]
	sh.mu.Lock()
	sk := sh.vhosts[100]
	sh.mu.Unlock()
	require.NotNil(t, sk)
	require.Equal(t, 256, sk.Width)
	require.Equal(t, 4, sk.Depth)

	rows, _ := p.drain(1)
	m := drainMap(rows)
	require.Equal(t, uint64(1), m[L7PathKey{TsUnixMin: 1, VhostID: 100, PathBucket: "/api", StatusBucket: 2}])
}

func TestPerVhostFair_PerShardNFloorAtOne(t *testing.T) {
	// trackedVhosts smaller than shard count still yields perShardN >= 1.
	p := newPerVhostFair(1, 8, 0, 0)
	require.Equal(t, 1, p.perShardN)
	p = newPerVhostFair(0, 8, 0, 0)
	require.Equal(t, 1, p.perShardN)
}

// TestPerVhostFair_ConcurrentDrainDuringReject runs record's lock-free reject
// branch (atomic.AddUint64 on sh.overflow) CONCURRENTLY with drain, which
// reads-and-clears the same counter. This is the regression guard for a
// write/write data race that existed when drain re-zeroed sh.overflow with a
// plain non-atomic store after the atomic Swap. Under -race, that plain store
// racing the concurrent atomic.Add is flagged. The assertion is just "no
// panic / completes" — exact counts under concurrency aren't deterministic;
// the point is to exercise reject+drain together for the race detector.
func TestPerVhostFair_ConcurrentDrainDuringReject(t *testing.T) {
	// trackedVhosts=16 -> perShardN = 1: each shard admits exactly one vhost,
	// so every other vhost congruent to that shard is rejected (overflow++).
	p := newPerVhostFair(16, 8, 0, 0)
	require.Equal(t, 1, p.perShardN)

	const recorders = 8
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Recorders: all use vhost_ids congruent to shard 0 (multiples of 16) so
	// after the first mover is admitted every subsequent record rejects via
	// the lock-free atomic.AddUint64(&sh.overflow, 1) path.
	for g := 0; g < recorders; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			vhostID := uint32((g + 1) * l7ShardCount) // 16, 32, 48, ... -> shard 0
			for {
				select {
				case <-stop:
					return
				default:
					p.record(vhostID, "/api", 2)
				}
			}
		}(g)
	}

	// Drainer: concurrently read-and-clear overflow in a tight loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			select {
			case <-stop:
				return
			default:
				p.drain(uint32(i))
			}
		}
	}()

	// Let reject and drain race for a while, then stop.
	for i := 0; i < 50000; i++ {
		p.record(l7ShardCount, "/api", 2) // also rejects on shard 0
	}
	close(stop)
	wg.Wait()

	// Final drain must not panic; counts under concurrency aren't asserted.
	require.NotPanics(t, func() { p.drain(1) })
}

func TestPerVhostFair_ConcurrentRecord(t *testing.T) {
	p := newPerVhostFair(64, 16, 0, 0)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				p.record(uint32(g), "/api", 2)
			}
		}(g)
	}
	wg.Wait()
	rows, _ := p.drain(1)
	m := drainMap(rows)
	for g := 0; g < 8; g++ {
		require.Equal(t, uint64(1000),
			m[L7PathKey{TsUnixMin: 1, VhostID: uint32(g), PathBucket: "/api", StatusBucket: 2}])
	}
}
