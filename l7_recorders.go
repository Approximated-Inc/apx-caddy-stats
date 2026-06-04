package apxstats

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/keilerkonzept/topk"
)

// l7ShardCount is the number of stripes the per-vhost-fair recorder splits
// its vhost map across. Sharding by vhost_id spreads lock contention under
// the high request rate of the L7 path track while keeping each vhost's
// counters on a single shard (so a vhost's per-shard cap is local).
const l7ShardCount = 16

// pvfShard is one stripe of the per-vhost-fair recorder. Each shard owns a
// disjoint set of vhost_ids (vhost_id % l7ShardCount) and its own TopK
// sketches + overflow counter, all guarded by mu.
type pvfShard struct {
	mu       sync.Mutex
	vhosts   map[uint32]*topk.Sketch // vhost_id -> top-k of combined items
	overflow uint64                  // vhosts rejected at cap this window
}

// perVhostFair is a sharded map[vhost_id]→TopK(k) recorder with first-mover
// admission: each shard tracks up to perShardN distinct vhosts, and once a
// shard is full a never-before-seen vhost in that shard is REJECTED (no
// eviction, no sentinel row) and counted in the shard's overflow. Within a
// tracked vhost, the top k (path_bucket, status_bucket) items are kept.
type perVhostFair struct {
	shards    [l7ShardCount]*pvfShard
	k         int // items (paths) per tracked vhost
	perShardN int // ceil(trackedVhosts / l7ShardCount), >= 1
	width     int // sketch width (0 -> library default)
	depth     int // sketch depth (0 -> library default)
}

// l7PathRow is one drained per-path counter: the fully-formed key (already
// stamped with the drain minute) plus its estimated request count.
type l7PathRow struct {
	Key   L7PathKey
	Count uint64
}

// newPerVhostFair builds a recorder tracking up to trackedVhosts distinct
// vhosts (spread evenly across the shards), keeping the top k paths per
// vhost. width/depth set the underlying TopK sketch dimensions; pass 0/0 to
// use the library defaults.
func newPerVhostFair(trackedVhosts, k, width, depth int) *perVhostFair {
	perShardN := (trackedVhosts + l7ShardCount - 1) / l7ShardCount
	if perShardN < 1 {
		perShardN = 1
	}
	p := &perVhostFair{
		k:         k,
		perShardN: perShardN,
		width:     width,
		depth:     depth,
	}
	for i := range p.shards {
		p.shards[i] = &pvfShard{vhosts: make(map[uint32]*topk.Sketch)}
	}
	return p
}

// newSketch builds a TopK sketch with the configured dimensions.
func (p *perVhostFair) newSketch() *topk.Sketch {
	if p.width > 0 && p.depth > 0 {
		return topk.New(p.k, topk.WithWidth(p.width), topk.WithDepth(p.depth))
	}
	return topk.New(p.k)
}

// combineItem packs (pathBucket, statusBucket) into the single string the
// TopK sketch tracks. pathBucket never contains a NUL byte (URL paths
// don't), so a NUL separator lets drain split it back unambiguously.
func combineItem(pathBucket string, statusBucket uint8) string {
	var b strings.Builder
	b.Grow(len(pathBucket) + 1)
	b.WriteString(pathBucket)
	b.WriteByte(0)
	b.WriteByte(statusBucket)
	return b.String()
}

// record counts one request for (vhostID, pathBucket, statusBucket). The
// vhost is sharded by vhost_id % l7ShardCount; within the shard a present
// vhost's sketch is incremented, an absent vhost is admitted if the shard is
// below perShardN, otherwise it's rejected (overflow++, no row emitted).
func (p *perVhostFair) record(vhostID uint32, pathBucket string, statusBucket uint8) {
	sh := p.shards[vhostID%l7ShardCount]
	item := combineItem(pathBucket, statusBucket)

	sh.mu.Lock()
	if sk, ok := sh.vhosts[vhostID]; ok {
		sk.Incr(item)
		sh.mu.Unlock()
		return
	}
	if len(sh.vhosts) < p.perShardN {
		sk := p.newSketch()
		sk.Incr(item)
		sh.vhosts[vhostID] = sk
		sh.mu.Unlock()
		return
	}
	sh.mu.Unlock()
	atomic.AddUint64(&sh.overflow, 1)
}

// drain snapshots every shard's tracked vhosts into l7PathRows stamped with
// drainMin, then resets each shard (fresh map + overflow 0) under the lock —
// snapshot-and-replace, like l7HvSnapshot. Returns the rows plus the total
// overflow (vhosts rejected at cap) across all shards this window.
func (p *perVhostFair) drain(drainMin uint32) ([]l7PathRow, uint64) {
	var rows []l7PathRow
	var totalOverflow uint64

	for _, sh := range p.shards {
		sh.mu.Lock()
		// overflow is incremented via atomic.Add in record (outside the
		// lock), so swap it atomically here too.
		totalOverflow += atomic.SwapUint64(&sh.overflow, 0)
		if len(sh.vhosts) == 0 {
			sh.mu.Unlock()
			continue
		}
		for vhostID, sk := range sh.vhosts {
			for _, it := range sk.SortedSlice() {
				if it.Count == 0 {
					continue
				}
				// The FIRST NUL is the separator: path buckets never contain
				// a NUL, so it's unambiguous even when the trailing status
				// byte is itself 0 (statusBucket==0 for out-of-range codes).
				idx := strings.IndexByte(it.Item, 0)
				if idx < 0 || idx+1 >= len(it.Item) {
					continue // malformed; should never happen
				}
				pathBucket := it.Item[:idx]
				statusBucket := it.Item[idx+1]
				rows = append(rows, l7PathRow{
					Key: L7PathKey{
						TsUnixMin:    drainMin,
						VhostID:      vhostID,
						PathBucket:   pathBucket,
						StatusBucket: statusBucket,
					},
					Count: uint64(it.Count),
				})
			}
		}
		// Reset the shard: snapshot-and-replace under the lock. overflow was
		// already zeroed by the atomic.SwapUint64 above; re-zeroing it here
		// with a plain write would race record's lock-free atomic.AddUint64.
		sh.vhosts = make(map[uint32]*topk.Sketch)
		sh.mu.Unlock()
	}

	return rows, totalOverflow
}
