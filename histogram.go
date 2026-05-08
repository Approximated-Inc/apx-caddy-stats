package apxstats

// HistogramBuckets is the number of latency buckets per Key. Mirrors the
// 16 lat_b00..lat_b15 columns in the analytics ClickHouse tables and the
// @bucket_count constant in lib/approximated/analytics/histogram.ex.
const HistogramBuckets = 16

// histogramUpperBoundsUs are the (exclusive) upper bounds of buckets 0..14
// in microseconds. Bucket 15 is +inf and has no entry here. Must match
// @upper_bounds_us in the Elixir Histogram module — the percentile math
// on the read side assumes these exact boundaries.
//
//	bucket 0  : <1ms      bucket 8  : <500ms
//	bucket 1  : <2ms      bucket 9  : <1s
//	bucket 2  : <5ms      bucket 10 : <2.5s
//	bucket 3  : <10ms     bucket 11 : <5s
//	bucket 4  : <25ms     bucket 12 : <10s
//	bucket 5  : <50ms     bucket 13 : <30s
//	bucket 6  : <100ms    bucket 14 : <60s
//	bucket 7  : <250ms    bucket 15 : +inf
var histogramUpperBoundsUs = [HistogramBuckets - 1]uint64{
	1_000, 2_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000,
	500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 30_000_000, 60_000_000,
}

// BucketForUs returns the histogram bucket index (0..15) for a duration
// in microseconds. Linear search over 15 small ints is faster than binary
// search at this size on modern CPUs (branch-predicted, cache-resident).
func BucketForUs(us uint64) int {
	for i, b := range histogramUpperBoundsUs {
		if us < b {
			return i
		}
	}
	return HistogramBuckets - 1
}
