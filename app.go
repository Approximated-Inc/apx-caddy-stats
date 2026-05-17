package apxstats

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&StatsApp{})
}

// AppRef is what handlers depend on. Production code uses *StatsApp;
// tests inject a stub.
type AppRef interface {
	// Record adds the given counter delta to the entry identified by k.
	// Lock-free on the hot path once k is in the map.
	Record(k Key, delta CounterDelta)
	// RecordUnique adds a hashed client identifier to the per-(vhost,minute)
	// set used by the unique-clients metric. No-op if HashSalt is empty.
	RecordUnique(tsUnixMin, vhostID uint32, hash uint64)
	// HashSalt returns the deployment salt for hashing client identifiers.
	// Empty string disables the unique-clients tracking entirely.
	HashSalt() string
	// ProxyServerID returns the cluster id this Caddy instance serves.
	ProxyServerID() uint32
}

// CounterDelta is what a single request contributes. The handler builds
// one of these per request and hands it to Record. Histograms are
// recorded as the bucket index that fires (LatBucket); we don't pass a
// 16-element array per request — only one bucket is ever non-zero.
type CounterDelta struct {
	BytesIn       uint64
	BytesOut      uint64
	DurationUs    uint64
	LatBucket     int // 0..HistogramBuckets-1
}

// IngestConfig describes where the app POSTs counter batches.
type IngestConfig struct {
	// URL is the absolute URL of the app endpoint that ingests batches.
	URL string `json:"url,omitempty"`
	// AuthEnvVar names the env var to source the shared secret from.
	// Default: APX_INTERNAL_KEY. The secret is sent as a plaintext
	// bearer in the AuthHeader on every POST — there is no HMAC,
	// no timestamp, no replay protection. Security relies on the
	// private mesh transport between Caddy machines and the
	// Approximated app, and on rotating APX_INTERNAL_KEY periodically.
	AuthEnvVar string `json:"auth_env_var,omitempty"`
	// AuthHeader is the HTTP header the shared-secret bearer rides on.
	// Default: apx-key.
	AuthHeader string `json:"auth_header,omitempty"`
	// FlushIntervalMs controls the periodic drain. Default 30000ms.
	FlushIntervalMs int `json:"flush_interval_ms,omitempty"`
	// MaxBufferRows caps the live counter map. New keys are dropped at the
	// cap; existing keys keep counting. Default 50000.
	MaxBufferRows int `json:"max_buffer_rows,omitempty"`
	// MaxUniqueHashes caps the total entries in the per-(vhost, minute)
	// unique-clients hash sets. Beyond the cap, new hashes are dropped
	// (existing ones remain — overflow doesn't lose accuracy on already-
	// tracked sets). Default 500000. Tune lower on memory-tight hosts;
	// higher on hosts with high traffic + many unique clients (NAT churn,
	// CDN backplane, scanners).
	MaxUniqueHashes int `json:"max_unique_hashes,omitempty"`
	// TimeoutMs bounds each POST. Default 10000ms.
	TimeoutMs int `json:"timeout_ms,omitempty"`
	// MaxRetries is the number of retries on POST failure before dropping
	// the batch. Default 3.
	MaxRetries int `json:"max_retries,omitempty"`
	// ShutdownMaxRetries is the retry budget used during the final flush
	// at Stop() (graceful shutdown / hot-reload). Higher than MaxRetries
	// because a brief ingest blip coinciding with a fleet-wide config
	// regen would otherwise lose data on every Caddy machine
	// simultaneously. Default 7.
	ShutdownMaxRetries int `json:"shutdown_max_retries,omitempty"`

	// L4SniMaxKeys caps the number of distinct SNIs the L4 SNI counter
	// map holds per machine per minute. Set by Approximated's
	// caddy_config_files.ex to 2 × the cluster's configured vhost count —
	// generous enough that legitimate traffic never overflows; tight
	// enough that an attacker spraying random SNIs hits the cap and rolls
	// into the L4SniOverflowSNI sentinel rather than ballooning the map.
	//
	// 0 / unset disables L4 SNI tracking entirely; an L4 handler can be
	// wired into the Caddy config but produces no rows until this field
	// is populated. Lets the module roll out before the operator has
	// provisioned the cap.
	L4SniMaxKeys int `json:"l4_sni_max_keys,omitempty"`
}

// StatsApp is the top-level Caddy App. One per Caddy process. Owns the
// counter map and the flush goroutine. Registered at module ID
// "apx_stats" so handlers fetch it via ctx.App("apx_stats").
type StatsApp struct {
	// ProxyServerIDValue identifies the Approximated cluster this Caddy
	// instance serves. Required.
	ProxyServerIDValue uint32 `json:"proxy_server_id"`

	// MachineID identifies which Caddy machine in the cluster this is.
	// Currently unused by the wire format (the app server tags by sender);
	// kept here for log/metric labels.
	MachineID string `json:"machine_id,omitempty"`

	// HashSaltValue is the per-deployment salt for hashing client
	// identifiers. Stamped into the Caddy config by the app's
	// `caddy_config_files.ex` rather than read from an env var on the
	// Caddy machine — that lets the operator rotate the salt by
	// regenerating the config (which propagates to all Caddy machines
	// via the existing config-check pull) instead of pushing new Fly
	// secrets and restarting machines.
	//
	// Empty string disables unique-clients tracking entirely (handlers
	// skip the hash, flush emits no uniques rows). Lets the module be
	// deployed before the operator has provisioned a salt.
	HashSaltValue string `json:"hash_salt,omitempty"`

	// Ingest is required.
	Ingest *IngestConfig `json:"ingest,omitempty"`

	logger   *zap.Logger
	secret   string
	hashSalt string
	client   *http.Client

	cfg ingestRuntime // resolved from Ingest with defaults applied

	// State is sharded across `shardCount` shards. Each shard owns its
	// own mutex + counters/uniques maps + counts; Record/RecordUnique
	// pick a shard by hashing the row's identifying fields so traffic
	// spreads across shards under contention. flushOnce snapshots every
	// shard in turn and ships the combined result.
	//
	// Sharding reduces the single-mutex contention point the original
	// design had at thousands of RPS/machine. Per-machine cardinality
	// for our typical cluster easily fits within one shard, but the
	// hot path (incrementing an existing counter) now contends with
	// 1/shardCount of the other goroutines on average.
	shards [shardCount]*counterShard

	overflow         uint64     // count of distinct new keys dropped due to MaxBufferRows
	overflowLogMu    sync.Mutex // guards overflowLoggedAt (cross-shard)
	overflowLoggedAt time.Time  // first-overflow log throttle (zero = never logged)
	uniquesOverflow  uint64     // count of unique-hash inserts dropped due to MaxUniqueHashes
	dropped          uint64     // count of rows dropped after retry exhaustion

	// L4 SNI counters live in a single mutexed map (no sharding) because
	// the cardinality is low — per cluster per minute, even under attack,
	// we expect at most low-thousands of distinct SNIs. A single mutex
	// across hundreds of cluster machines doesn't contend meaningfully
	// at L4-connection rates (which are an order of magnitude below
	// HTTP-request rates). Cap is a per-machine bound; the
	// L4SniOverflowSNI sentinel captures dropped increments so the
	// "overflow happened" signal isn't lost even when individual SNIs
	// are.
	l4SniMu       sync.Mutex
	l4SniMap      map[L4SniKey]*l4SniCounter
	l4SniOverflow uint64 // dropped-due-to-cap count for the current minute window

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// shardCount controls how many independent (mutex, counters, uniques)
// triplets the StatsApp maintains. A power of two so we can use bitmask
// indexing on the hash output. 16 gives a comfortable ratio of
// contention reduction to memory overhead — at 64-byte average key
// payload × ~1000 active keys per shard, we're a few hundred KB per
// shard. Tune up if profiling shows per-shard contention on a
// dominantly-single-vhost workload.
const shardCount = 16
const shardMask = shardCount - 1

type counterShard struct {
	mu              sync.Mutex
	counters        map[Key]*Counter
	uniques         map[uniqueKey]map[uint64]struct{}
	uniqueHashCount uint64
}

type ingestRuntime struct {
	url                string
	authHeader         string
	flushInterval      time.Duration
	maxBuffer          int
	maxUniqueHashes    int
	maxRetries         int
	shutdownMaxRetries int
	// l4SniMaxKeys is the per-minute cap on distinct SNIs in the L4 SNI
	// counter map. 0 disables L4 SNI tracking; the handler still runs
	// but RecordL4Sni is a no-op so no map memory is allocated.
	l4SniMaxKeys int
}

// CaddyModule registers the app at root ID "apx_stats".
func (*StatsApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "apx_stats",
		New: func() caddy.Module { return new(StatsApp) },
	}
}

// Provision validates config, reads the shared-secret bearer token,
// builds the HTTP client, and initializes the counter map. Called by
// Caddy before Start. The secret is plaintext bearer auth — no HMAC,
// no replay protection — see IngestConfig.AuthEnvVar.
func (a *StatsApp) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	if a.Ingest == nil {
		return fmt.Errorf("apx_stats app: ingest config is required")
	}
	if a.Ingest.URL == "" {
		return fmt.Errorf("apx_stats app: ingest.url is required")
	}
	if a.ProxyServerIDValue == 0 {
		return fmt.Errorf("apx_stats app: proxy_server_id is required")
	}

	envVar := a.Ingest.AuthEnvVar
	if envVar == "" {
		envVar = "APX_INTERNAL_KEY"
	}
	a.secret = os.Getenv(envVar)
	if a.secret == "" {
		return fmt.Errorf("apx_stats app: %s env var is empty", envVar)
	}

	// Hash salt comes from the config blob directly (not an env var) so
	// the operator can rotate it by regenerating Caddy config. Optional —
	// empty disables unique-clients tracking without crashing Caddy.
	a.hashSalt = a.HashSaltValue

	a.cfg = ingestRuntime{
		url:                a.Ingest.URL,
		authHeader:         firstNonEmpty(a.Ingest.AuthHeader, "apx-key"),
		flushInterval:      durationMs(a.Ingest.FlushIntervalMs, 30_000),
		maxBuffer:          intDefault(a.Ingest.MaxBufferRows, 50_000),
		maxUniqueHashes:    intDefault(a.Ingest.MaxUniqueHashes, 500_000),
		maxRetries:         intDefault(a.Ingest.MaxRetries, 3),
		shutdownMaxRetries: intDefault(a.Ingest.ShutdownMaxRetries, 7),
		// L4 SNI cap: no default fallback. 0 means "disabled"; the
		// Approximated control plane sets this explicitly via the
		// `l4_sni_max_keys` config field based on the cluster's vhost
		// count. Leaving it 0 in dev / before Phoenix wires it through
		// is fine — RecordL4Sni becomes a no-op.
		l4SniMaxKeys: a.Ingest.L4SniMaxKeys,
	}

	a.client = &http.Client{
		Timeout: durationMs(a.Ingest.TimeoutMs, 10_000),
		Transport: &http.Transport{
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	perShardInitialCap := a.cfg.maxBuffer / (8 * shardCount)
	if perShardInitialCap < 8 {
		perShardInitialCap = 8
	}
	for i := range a.shards {
		a.shards[i] = &counterShard{
			counters: make(map[Key]*Counter, perShardInitialCap),
			uniques:  make(map[uniqueKey]map[uint64]struct{}),
		}
	}
	a.l4SniMap = make(map[L4SniKey]*l4SniCounter)
	a.stopCh = make(chan struct{})
	return nil
}

// shardForKey maps a Key to its owning shard. Uses an FNV-1a 64-bit
// hash over the variable-cardinality fields (TsUnixMin omitted since
// it's near-constant during a flush window — would cluster traffic in
// one shard).
func (a *StatsApp) shardForKey(k Key) *counterShard {
	h := uint64(14695981039346656037) // fnv1a offset basis
	h = mixUint32(h, k.VhostID)
	h = mixUint16(h, k.Status)
	h = mixString(h, k.Method)
	h = mixString(h, k.Origin)
	h = mixString(h, k.Country)
	h = mixUint32(h, k.ASN)
	return a.shards[h&shardMask]
}

// shardForUnique mirrors the per-(vhost, minute) split. The TsUnixMin
// here is intentionally part of the key (different from shardForKey)
// because uniques accumulate per minute and we want them spread across
// shards as time advances.
func (a *StatsApp) shardForUnique(t, v uint32) *counterShard {
	h := uint64(14695981039346656037)
	h = mixUint32(h, t)
	h = mixUint32(h, v)
	return a.shards[h&shardMask]
}

// FNV-1a mixers — each byte XORed in, then multiplied by FNV prime.
const fnv1aPrime = 1099511628211

func mixUint32(h uint64, v uint32) uint64 {
	for i := 0; i < 4; i++ {
		h ^= uint64(byte(v >> (i * 8)))
		h *= fnv1aPrime
	}
	return h
}

func mixUint16(h uint64, v uint16) uint64 {
	h ^= uint64(byte(v))
	h *= fnv1aPrime
	h ^= uint64(byte(v >> 8))
	h *= fnv1aPrime
	return h
}

func mixString(h uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnv1aPrime
	}
	return h
}

// Start launches the periodic flush goroutine.
func (a *StatsApp) Start() error {
	a.wg.Add(1)
	go a.flushLoop()
	return nil
}

// Stop signals the flush goroutine to drain once more and exit.
func (a *StatsApp) Stop() error {
	a.stopOnce.Do(func() { close(a.stopCh) })
	a.wg.Wait()
	return nil
}

// ProxyServerID exposes the cluster id to handlers.
func (a *StatsApp) ProxyServerID() uint32 { return a.ProxyServerIDValue }

// Test-only accessors. The counters / uniques maps are sharded for
// contention reduction; tests want to peek at aggregate state without
// caring which shard owns a given key.

func (a *StatsApp) counterCount() int {
	total := 0
	for _, s := range a.shards {
		s.mu.Lock()
		total += len(s.counters)
		s.mu.Unlock()
	}
	return total
}

func (a *StatsApp) counterFor(k Key) (*Counter, bool) {
	s := a.shardForKey(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.counters[k]
	return c, ok
}

func (a *StatsApp) countersSnapshot() map[Key]*Counter {
	out := make(map[Key]*Counter)
	for _, s := range a.shards {
		s.mu.Lock()
		for k, c := range s.counters {
			out[k] = c
		}
		s.mu.Unlock()
	}
	return out
}

func (a *StatsApp) uniqueHashTotal() uint64 {
	var total uint64
	for _, s := range a.shards {
		s.mu.Lock()
		total += s.uniqueHashCount
		s.mu.Unlock()
	}
	return total
}

func (a *StatsApp) uniquesEmpty() bool {
	for _, s := range a.shards {
		s.mu.Lock()
		empty := len(s.uniques) == 0
		s.mu.Unlock()
		if !empty {
			return false
		}
	}
	return true
}

// HashSalt exposes the deployment salt for hashing client identifiers.
// Empty string disables unique-clients tracking — handlers should skip
// computing the hash when this returns "".
func (a *StatsApp) HashSalt() string { return a.hashSalt }

// RecordUnique adds a hashed client identifier to the per-(vhost,minute)
// set. Called once per request from the handler. No-op when the salt is
// unset (HashSalt() == "") so an unconfigured deployment doesn't waste
// memory accumulating sets it can't ship.
//
// Sharded the same way Record is — shardForUnique(tsUnixMin, vhostID)
// picks the owning shard, only that shard's mutex is held. Map
// allocation for new (vhost, minute) keys is amortized by per-shard
// `len(uniques)` staying small (~one entry per active vhost per minute
// per shard).
func (a *StatsApp) RecordUnique(tsUnixMin, vhostID uint32, hash uint64) {
	if a.hashSalt == "" {
		return
	}

	k := uniqueKey{TsUnixMin: tsUnixMin, VhostID: vhostID}
	s := a.shardForUnique(tsUnixMin, vhostID)
	// Per-shard cap so each shard gets a fair slice of the global
	// budget. Picks shard count as the divisor so the SUM of shard caps
	// equals the configured global cap.
	perShardCap := uint64(a.cfg.maxUniqueHashes / shardCount)

	s.mu.Lock()
	defer s.mu.Unlock()

	set, ok := s.uniques[k]
	if !ok {
		// New (vhost, minute) key: also bounded by per-shard cap —
		// if we're already at the cap, drop the row entirely rather
		// than allocate a new set.
		if s.uniqueHashCount >= perShardCap {
			atomic.AddUint64(&a.uniquesOverflow, 1)
			metricUniquesOverflow.Inc()
			return
		}
		set = make(map[uint64]struct{}, 16)
		s.uniques[k] = set
	}

	// Existing-set insert: drop the hash if shard count is at cap.
	// Sets that already contain a value can't grow further, but they
	// still count their existing entries against the cap. During
	// overflow we keep existing distinct-clients but stop discovering
	// new ones — preferable to losing the row entirely.
	if _, exists := set[hash]; exists {
		return
	}
	if s.uniqueHashCount >= perShardCap {
		atomic.AddUint64(&a.uniquesOverflow, 1)
		metricUniquesOverflow.Inc()
		return
	}
	set[hash] = struct{}{}
	s.uniqueHashCount++
}

// Record adds delta to the counter at k, inserting a new entry if absent.
//
// Takes the per-shard mutex through the increments. An earlier version
// released the mutex before doing per-field atomic.Add on the
// *Counter, but that raced with flushOnce: between the unlock and the
// atomic.Add a concurrent flushOnce could swap the map and the encode
// loop could read the field, so the late add landed on a *Counter that
// was no longer reachable through the live map and had already been
// encoded without it — the increment was lost. Plain field reads in
// the encoder against atomic writes here was also a Go data race per
// the memory model, which `go test -race` would catch.
//
// Holding the shard mutex through the increments closes both: any
// Record that gets the lock before flushOnce completes its mutations
// before flushOnce can swap; any Record that gets the lock after
// flushOnce looks up from the new map. Sharding reduces contention by
// spreading writers across shardCount independent locks; the
// per-shard work is otherwise identical to the pre-sharding version.
// chain around it.
func (a *StatsApp) Record(k Key, delta CounterDelta) {
	s := a.shardForKey(k)
	perShardCap := a.cfg.maxBuffer / shardCount

	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.counters[k]
	if !ok {
		if len(s.counters) >= perShardCap {
			atomic.AddUint64(&a.overflow, 1)
			metricBufferOverflow.Inc()
			a.maybeLogOverflow()
			return
		}
		c = &Counter{}
		s.counters[k] = c
	}

	c.RequestCount++
	c.BytesIn += delta.BytesIn
	c.BytesOut += delta.BytesOut
	c.DurationUsSum += delta.DurationUs
	if i := delta.LatBucket; i >= 0 && i < HistogramBuckets {
		c.LatBuckets[i]++
	}
}

// RecordL4Sni increments the L4 SNI counter for the given SNI in the
// current minute bucket. Called once per accepted L4 connection from the
// `apx_l4_stats` handler.
//
// If the per-machine cap (`L4SniMaxKeys`) is set and the map is at the
// cap with a new SNI key, the increment rolls into the
// L4SniOverflowSNI sentinel counter — keeps the "overflow happened"
// signal observable even when individual SNIs are dropped.
//
// `cap <= 0` disables tracking entirely (no-op). Empty `sni` collapses
// to the `__empty__` sentinel so absence-of-SNI is distinguishable from
// dropped-by-cap.
func (a *StatsApp) RecordL4Sni(sni string) {
	if a.cfg.l4SniMaxKeys <= 0 {
		if a.logger != nil {
			a.logger.Debug("apx_stats: RecordL4Sni called but l4SniMaxKeys is 0 — skipping",
				zap.String("sni", sni))
		}
		return
	}
	if sni == "" {
		sni = L4SniEmptySNI
	}

	if a.logger != nil {
		a.logger.Debug("apx_stats: RecordL4Sni",
			zap.String("sni", sni),
			zap.Int("cap", a.cfg.l4SniMaxKeys))
	}

	k := L4SniKey{
		TsUnixMin: uint32(time.Now().Unix() / 60),
		SNI:       sni,
	}

	a.l4SniMu.Lock()
	defer a.l4SniMu.Unlock()

	if c, ok := a.l4SniMap[k]; ok {
		c.ConnectionCount++
		return
	}

	if len(a.l4SniMap) >= a.cfg.l4SniMaxKeys {
		// New key at cap — count toward the overflow sentinel for this
		// minute. The sentinel itself is a real map entry once any
		// overflow has happened.
		overflowKey := L4SniKey{TsUnixMin: k.TsUnixMin, SNI: L4SniOverflowSNI}
		if c, ok := a.l4SniMap[overflowKey]; ok {
			c.ConnectionCount++
		} else {
			a.l4SniMap[overflowKey] = &l4SniCounter{ConnectionCount: 1}
		}
		atomic.AddUint64(&a.l4SniOverflow, 1)
		return
	}

	a.l4SniMap[k] = &l4SniCounter{ConnectionCount: 1}
}

// l4SniSnapshot atomically swaps the in-memory L4 SNI map and returns
// the previous contents. Called from flushOnce.
func (a *StatsApp) l4SniSnapshot() map[L4SniKey]*l4SniCounter {
	a.l4SniMu.Lock()
	defer a.l4SniMu.Unlock()
	if len(a.l4SniMap) == 0 {
		return nil
	}
	snap := a.l4SniMap
	a.l4SniMap = make(map[L4SniKey]*l4SniCounter)
	return snap
}

// drainL4SniRows snapshots and renders rows for shipping. Rows with
// `ConnectionCount <= 1` are dropped (single-occurrence SNIs dominate
// the long tail under attack and have zero relevance to the auto-block
// threshold — keeping them would multiply ingest volume by 10-100×).
// The L4SniOverflowSNI sentinel row is always shipped if present —
// losing visibility on cap-hit events would be worse than keeping a
// 1-count overflow row.
func (a *StatsApp) drainL4SniRows() map[L4SniKey]*l4SniCounter {
	snap := a.l4SniSnapshot()
	if snap == nil {
		if a.logger != nil {
			a.logger.Debug("apx_stats: drainL4SniRows — l4SniMap was empty")
		}
		return nil
	}
	out := make(map[L4SniKey]*l4SniCounter, len(snap))
	dropped := 0
	for k, c := range snap {
		if c.ConnectionCount <= 1 && k.SNI != L4SniOverflowSNI {
			dropped++
			continue
		}
		out[k] = c
	}
	if a.logger != nil {
		a.logger.Debug("apx_stats: drainL4SniRows",
			zap.Int("pre_filter_keys", len(snap)),
			zap.Int("dropped_count_le_1", dropped),
			zap.Int("kept_keys", len(out)))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// maybeLogOverflow emits a single zap.Warn the first time the buffer
// hits its cap, and at most once per minute thereafter. Without this,
// overflow showed up only as a Prometheus counter — useful for graphs
// but invisible during incident response when an operator is reading
// logs. Uses overflowLogMu (cross-shard) since multiple shards can hit
// overflow concurrently.
func (a *StatsApp) maybeLogOverflow() {
	now := time.Now()

	a.overflowLogMu.Lock()
	if !a.overflowLoggedAt.IsZero() && now.Sub(a.overflowLoggedAt) < time.Minute {
		a.overflowLogMu.Unlock()
		return
	}
	a.overflowLoggedAt = now
	a.overflowLogMu.Unlock()

	if a.logger != nil {
		a.logger.Warn("apx_stats: buffer overflow — dropping new counter keys",
			zap.Int("max_buffer_rows", a.cfg.maxBuffer),
			zap.Uint64("overflow_total", atomic.LoadUint64(&a.overflow)),
		)
	}
}

// flushLoop runs until Stop is called. On each tick it drains the
// current counter map and ships it. On Stop it does one final drain so
// shutdown loses ≤ flushInterval of buffered counters.
func (a *StatsApp) flushLoop() {
	defer a.wg.Done()
	t := time.NewTicker(a.cfg.flushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.flushOnce(a.cfg.maxRetries)
		case <-a.stopCh:
			// Shutdown flush gets a wider retry budget than a steady-
			// state tick: Caddy hot-reloads create a new App instance
			// and call Stop() on the old one. If the old App's final
			// flush fails after the normal 3-retry budget (~3.4s), the
			// buffer is dropped — and on a cluster with per-minute
			// config_regen_immediate, a brief ingest hiccup can lose
			// fleet-wide data simultaneously. Up to 7 retries (~30s
			// total backoff) gives more leeway, still well under Fly's
			// 60s graceful-shutdown SIGKILL window.
			a.flushOnce(a.cfg.shutdownMaxRetries)
			return
		}
	}
}

// flushOnce drains every shard's counter + uniques maps into one
// combined snapshot, encodes both as gzipped NDJSON, and POSTs it
// with `maxRetries` retries. Counter and uniques rows ride the same
// wire — the app-side ingest controller distinguishes by row shape
// (presence of `client_hashes`).
//
// Locks each shard in turn (not all-at-once) so a request hitting an
// already-drained shard isn't blocked on the rest of the drain. The
// trade-off: a request landing during the drain may write to either
// the old (about-to-be-shipped) snapshot or the fresh map depending on
// timing, but either way its data ships within the next flush
// interval. No data loss.
func (a *StatsApp) flushOnce(maxRetries int) {
	perShardInitialCap := a.cfg.maxBuffer / (8 * shardCount)
	if perShardInitialCap < 8 {
		perShardInitialCap = 8
	}

	snap := make(map[Key]*Counter)
	uniqSnap := make(map[uniqueKey]map[uint64]struct{})

	for _, s := range a.shards {
		s.mu.Lock()
		if len(s.counters) == 0 && len(s.uniques) == 0 {
			s.mu.Unlock()
			continue
		}
		for k, c := range s.counters {
			snap[k] = c
		}
		for k, set := range s.uniques {
			uniqSnap[k] = set
		}
		s.counters = make(map[Key]*Counter, perShardInitialCap)
		s.uniques = make(map[uniqueKey]map[uint64]struct{})
		s.uniqueHashCount = 0
		s.mu.Unlock()
	}

	l4SniSnap := a.drainL4SniRows()

	if a.logger != nil {
		a.logger.Debug("apx_stats: flushOnce summary",
			zap.Int("http_counter_rows", len(snap)),
			zap.Int("uniques_rows", len(uniqSnap)),
			zap.Int("l4_sni_rows_after_filter", len(l4SniSnap)))
	}

	if len(snap) == 0 && len(uniqSnap) == 0 && len(l4SniSnap) == 0 {
		return
	}

	rowCount := len(snap) + len(uniqSnap) + len(l4SniSnap)
	metricBufferSize.Set(float64(rowCount))

	body, err := encodeBatch(a.ProxyServerIDValue, snap, uniqSnap, l4SniSnap)
	if err != nil {
		atomic.AddUint64(&a.dropped, uint64(rowCount))
		metricDroppedRows.Add(float64(rowCount))
		if a.logger != nil {
			a.logger.Warn("apx_stats: encode batch failed", zap.Error(err))
		}
		return
	}

	if err := a.shipWithRetryN(body, maxRetries); err != nil {
		atomic.AddUint64(&a.dropped, uint64(rowCount))
		metricDroppedRows.Add(float64(rowCount))
		if a.logger != nil {
			a.logger.Warn("apx_stats: ship failed; dropping batch",
				zap.Int("rows", rowCount),
				zap.Error(err),
			)
		}
	}
}

// shipWithRetry POSTs body. Retries on transport error or 5xx, with a
// short exponential backoff. 4xx responses are NOT retried — they
// indicate a wire-format/auth problem that retries won't fix.
func (a *StatsApp) shipWithRetry(body []byte) error {
	return a.shipWithRetryN(body, a.cfg.maxRetries)
}

// shipWithRetryN is like shipWithRetry but takes the retry budget as a
// parameter — used by the shutdown path so a Stop() coinciding with an
// ingest blip can use a wider retry window without temporarily mutating
// `a.cfg` (which would be a goroutine-safety hazard if any other flush
// path were ever to run concurrently).
func (a *StatsApp) shipWithRetryN(body []byte, maxRetries int) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff(attempt))
		}
		err := a.shipOnce(body)
		if err == nil {
			metricShipAttempts.WithLabelValues("ok").Inc()
			return nil
		}
		lastErr = err
		if isPermanent(err) {
			metricShipAttempts.WithLabelValues("permanent").Inc()
			return err
		}
		metricShipAttempts.WithLabelValues("transient").Inc()
	}
	return lastErr
}

func (a *StatsApp) shipOnce(body []byte) error {
	start := time.Now()
	defer func() {
		metricShipDuration.Observe(time.Since(start).Seconds())
	}()

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		a.cfg.url,
		bytes.NewReader(body),
	)
	if err != nil {
		return permanentErr{err}
	}
	// Plaintext shared-secret bearer (NOT HMAC). The Approximated app
	// verifies via the ApxKeyAuth plug. Anyone with this secret can
	// forge a batch; rotate APX_INTERNAL_KEY + config-regen Caddy to
	// invalidate stolen secrets.
	req.Header.Set(a.cfg.authHeader, a.secret)
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := a.client.Do(req)
	if err != nil {
		return err // transport errors are transient
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// 4xx: don't retry. Auth or wire-format problem.
		return permanentErr{fmt.Errorf("ingest %d", resp.StatusCode)}
	default:
		return fmt.Errorf("ingest %d", resp.StatusCode)
	}
}

// permanentErr marks an error as not worth retrying.
type permanentErr struct{ error }

func isPermanent(err error) bool {
	_, ok := err.(permanentErr)
	return ok
}

// encodeBatch builds the gzipped NDJSON body for a snapshot. One JSON
// object per line. Each row carries a `_type` discriminator
// (`"counter"`, `"uniques"`, and eventually `"event"`) so the app-side
// ingest controller can dispatch on type rather than infer from
// shape. Counter rows have the existing dimension+counter fields;
// uniques rows carry `client_hashes` and only the
// (ts/proxy_server_id/vhost_id) key fields. Histogram buckets are
// emitted sparsely — buckets with zero counts are omitted to keep the
// wire small.
func encodeBatch(proxyServerID uint32, snap map[Key]*Counter, uniqSnap map[uniqueKey]map[uint64]struct{}, l4SniSnap map[L4SniKey]*l4SniCounter) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	for k, c := range snap {
		if err := encodeRow(gz, proxyServerID, k, c); err != nil {
			return nil, err
		}
	}
	for uk, set := range uniqSnap {
		if err := encodeUniquesRow(gz, proxyServerID, uk, set); err != nil {
			return nil, err
		}
	}
	for k, c := range l4SniSnap {
		if err := encodeL4SniRow(gz, proxyServerID, k, c); err != nil {
			return nil, err
		}
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeL4SniRow writes one NDJSON line for an L4 SNI counter entry.
// Format:
//
//	{"_type":"l4_sni","ts":"...","proxy_server_id":N,"sni":"...","connection_count":N}
//
// Matches the contract in
// `lib/approximated_web/controllers/analytics_ingest_controller.ex` —
// the `normalize_l4_sni_row/1` clause.
func encodeL4SniRow(w *gzip.Writer, ps uint32, k L4SniKey, c *l4SniCounter) error {
	var b strings.Builder
	b.Grow(128)
	b.WriteByte('{')
	writeString(&b, "_type", "l4_sni")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(k.TsUnixMin))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "sni", k.SNI)
	b.WriteByte(',')
	writeUint64(&b, "connection_count", c.ConnectionCount)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// encodeUniquesRow writes one NDJSON line for a uniques entry. Format:
//
//	{"_type": "uniques", "ts": "...", "proxy_server_id": N, "vhost_id": N, "client_hashes": [h1, h2, ...]}
//
// The app-side controller dispatches on `_type` so future row kinds
// (e.g., "event") can be added without inferring from shape.
func encodeUniquesRow(w *gzip.Writer, ps uint32, uk uniqueKey, set map[uint64]struct{}) error {
	if len(set) == 0 {
		return nil
	}
	var b strings.Builder
	b.Grow(64 + 12*len(set))
	b.WriteByte('{')
	writeString(&b, "_type", "uniques")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(uk.TsUnixMin))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeUint32(&b, "vhost_id", uk.VhostID)
	b.WriteString(`,"client_hashes":[`)
	first := true
	for h := range set {
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(strconv.FormatUint(h, 10))
	}
	b.WriteString("]}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// encodeRow writes one NDJSON line. Hand-rolled to avoid encoding/json
// reflection overhead per row and to handle the sparse histogram fields
// without an intermediate map allocation.
func encodeRow(w *gzip.Writer, ps uint32, k Key, c *Counter) error {
	var b strings.Builder
	b.Grow(256)
	b.WriteByte('{')

	writeString(&b, "_type", "counter")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(k.TsUnixMin))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeUint32(&b, "vhost_id", k.VhostID)
	b.WriteByte(',')
	writeString(&b, "method", k.Method)
	b.WriteByte(',')
	writeUint16(&b, "status", k.Status)
	b.WriteByte(',')
	writeString(&b, "origin", k.Origin)
	b.WriteByte(',')
	writeString(&b, "country", k.Country)
	b.WriteByte(',')
	writeUint32(&b, "asn", k.ASN)
	b.WriteByte(',')
	writeUint64(&b, "request_count", c.RequestCount)
	b.WriteByte(',')
	writeUint64(&b, "bytes_in", c.BytesIn)
	b.WriteByte(',')
	writeUint64(&b, "bytes_out", c.BytesOut)
	b.WriteByte(',')
	writeUint64(&b, "duration_us_sum", c.DurationUsSum)

	for i, n := range c.LatBuckets {
		if n == 0 {
			continue
		}
		b.WriteByte(',')
		writeUint64(&b, histKey(i), n)
	}

	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// writeString writes a JSON `"key":"val"` pair. `val` is JSON-string
// escaped via encoding/json fallback when needed; we expect ASCII-clean
// inputs (method, origin, country, ISO timestamp) so the fast path
// handles 99.9% of cases.
func writeString(b *strings.Builder, key, val string) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	if needsJSONEscape(val) {
		b.WriteString(jsonEscape(val))
	} else {
		b.WriteByte('"')
		b.WriteString(val)
		b.WriteByte('"')
	}
}

func writeUint16(b *strings.Builder, key string, n uint16) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	b.WriteString(strconv.FormatUint(uint64(n), 10))
}

func writeUint32(b *strings.Builder, key string, n uint32) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	b.WriteString(strconv.FormatUint(uint64(n), 10))
}

func writeUint64(b *strings.Builder, key string, n uint64) {
	b.WriteByte('"')
	b.WriteString(key)
	b.WriteString(`":`)
	b.WriteString(strconv.FormatUint(n, 10))
}

func needsJSONEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == '"' || c == '\\' || c >= 0x80 {
			return true
		}
	}
	return false
}

// jsonEscape uses encoding/json's escaping rules via Marshal. The
// fast-path string writer handles >99% of inputs without taking this
// path, so the per-call cost is fine for the rare exotic header value.
func jsonEscape(s string) string {
	// Inlined minimal escaping. Avoids importing encoding/json just for
	// the slow path — keeps dependencies tight. Handles control chars,
	// quotes, backslashes; non-ASCII passes through (ECMA-404 allows it).
	var out strings.Builder
	out.Grow(len(s) + 2)
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case c == '\n':
			out.WriteString(`\n`)
		case c == '\r':
			out.WriteString(`\r`)
		case c == '\t':
			out.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(&out, `\u%04x`, c)
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
	return out.String()
}

// firstNonEmpty returns the first non-empty string in args, or "".
func firstNonEmpty(args ...string) string {
	for _, s := range args {
		if s != "" {
			return s
		}
	}
	return ""
}

func intDefault(n, def int) int {
	if n > 0 {
		return n
	}
	return def
}

func durationMs(n, def int) time.Duration {
	if n <= 0 {
		n = def
	}
	return time.Duration(n) * time.Millisecond
}

// backoff returns a sleep duration for retry attempt i (1-indexed).
// 200ms, 800ms, 2.4s — bounded so a long flush doesn't cause the next
// tick to fire on top of an in-flight retry.
func backoff(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 200 * time.Millisecond
	case 2:
		return 800 * time.Millisecond
	default:
		return 2400 * time.Millisecond
	}
}

// Overflow returns the cumulative count of new keys dropped due to the
// buffer cap. Exposed for tests + observability.
func (a *StatsApp) Overflow() uint64 { return atomic.LoadUint64(&a.overflow) }

// Dropped returns the cumulative count of rows dropped after retry
// exhaustion or encode failure.
func (a *StatsApp) Dropped() uint64 { return atomic.LoadUint64(&a.dropped) }

var (
	_ caddy.App         = (*StatsApp)(nil)
	_ caddy.Provisioner = (*StatsApp)(nil)
	_ AppRef            = (*StatsApp)(nil)
)
