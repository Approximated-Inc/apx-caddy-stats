package apxstats

// L4SniKey is the natural identity of an aggregated L4 SNI counter row.
// Like `Key`, ProxyServerID is global per Caddy process (set on StatsApp
// at provision) so it's not part of the key. Unlike `Key`, no MachineID
// dimension — the Phoenix-side ingest controller relies on
// SummingMergeTree's cross-machine merge.
type L4SniKey struct {
	TsUnixMin uint32 // unix minute, fits 2106
	SNI       string // server name from TLS ClientHello, "" if absent
}

// L4SniOverflowSNI is the synthetic SNI emitted when the per-machine map
// cap is hit. Its connection_count is the sum of dropped same-minute
// increments for new SNIs the map didn't have room for. Keeps the
// per-(cluster, minute) "overflow happened" signal observable even when
// individual SNIs were dropped.
const L4SniOverflowSNI = "__overflow__"

// L4SniEmptySNI is the synthetic SNI emitted when the L4 handler reads
// an empty server-name from the ClientHello (e.g., raw TLS with no SNI
// extension, or matcher var not set). Distinguishes "no SNI presented"
// from genuinely unknown.
const L4SniEmptySNI = "__empty__"

// l4SniCounter holds the aggregated count for one L4SniKey. Separate
// type from Counter because the L4 SNI track has only one scalar (no
// bytes, no latency histogram) — a connection arrived and was counted.
type l4SniCounter struct {
	ConnectionCount uint64
}
