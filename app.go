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
	"github.com/keilerkonzept/topk"
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
	// RecordRequestEvent feeds one raw per-(served)-request analytics row
	// into the request_events recorder. No-op when the recorder is nil
	// (track off — gated internally). The served-only filter lives at the
	// handler call site, not here.
	RecordRequestEvent(row requestEventRow)
	// RecordChallengeAttempt increments the per-(vhost, ip, outcome)
	// challenge-attempt counter. Called once per request that carries an
	// `apx_challenge_outcome` var. Nil-safe.
	RecordChallengeAttempt(key challengeAttemptKey)
	// RecordEdgeVerifyAttempt increments the per-(vhost, path_bucket,
	// outcome) edge-verify-attempt counter. Called once per request
	// that carries an `apx_verify_outcome` var. Nil-safe.
	RecordEdgeVerifyAttempt(key edgeVerifyAttemptKey)
	// HashSalt returns the deployment salt for hashing client identifiers.
	// Empty string disables the unique-clients tracking entirely.
	HashSalt() string
	// ProxyServerID returns the cluster id this Caddy instance serves.
	ProxyServerID() uint32
	// MachineID returns the emitting machine's identifier (app MachineID
	// config), stamped on mode_v2 request_event rows. May be "".
	MachineID() string
	// RequestEventsModeV2 reports whether the request_events track runs in
	// mode_v2 (unsampled served rows, blocked/challenge rows logged with a
	// disposition, extra wire fields). False → legacy behavior.
	RequestEventsModeV2() bool
}

// CounterDelta is what a single request contributes. The handler builds
// one of these per request and hands it to Record. Histograms are
// recorded as the bucket index that fires (LatBucket); we don't pass a
// 16-element array per request — only one bucket is ever non-zero.
type CounterDelta struct {
	BytesIn    uint64
	BytesOut   uint64
	DurationUs uint64
	LatBucket  int // 0..HistogramBuckets-1
}

// IngestConfig describes where the app POSTs counter batches.
type IngestConfig struct {
	// URL is the absolute URL of the app endpoint that ingests batches.
	URL string `json:"url,omitempty"`
	// AuthToken, when set, is the shared-secret bearer sent on every POST,
	// sourced directly from the config blob (like hash_salt) so the control
	// plane can rotate it per-cluster with a config regen — no env var, no
	// machine restart. When empty, falls back to reading AuthEnvVar.
	AuthToken string `json:"auth_token,omitempty"`
	// AuthEnvVar names the env var to source the shared secret from when
	// AuthToken is unset. Default: APX_INTERNAL_KEY. The secret is sent as a plaintext
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

	// FingerprintMaxKeys / FingerprintIpMaxKeys cap distinct keys per machine
	// per minute for the two fingerprint maps. 0 disables the track (no-op
	// RecordFingerprint, no map allocation) — the per-cluster kill switch.
	FingerprintMaxKeys   int `json:"fingerprint_max_keys,omitempty"`
	FingerprintIpMaxKeys int `json:"fingerprint_ip_max_keys,omitempty"`

	// CorazaMaxEvents caps the raw per-(request, rule) WAF detection slice
	// per flush window. 0 / unset falls back to CorazaMaxEventsDefault
	// (this track does NOT disable on 0 — the WAF config's
	// `SecAuditLogType apx_stats` is what gates recording). Events beyond
	// the cap are dropped and counted in corazaOverflow.
	CorazaMaxEvents int `json:"coraza_max_events,omitempty"`

	// RequestEvents gates and bounds the raw per-request analytics track
	// (request_event rows). Phoenix emits the `ingest.request_events` block
	// (`enabled`/`sample_threshold`/`max_rows`) when the reqevents feature is
	// on; absent / `{enabled:false}` keeps the track OFF (no recorder, no
	// allocation, RecordRequestEvent is a no-op).
	RequestEvents *RequestEventsConfig `json:"request_events,omitempty"`
}

// RequestEventsConfig gates and bounds the request_events recorder. Enabled
// builds the recorder at Provision; SampleThreshold is the per-window emit
// count above which the recorder samples under load (<=0 → never sample,
// every served row kept); MaxRows caps rows/window (0 → default 200_000).
type RequestEventsConfig struct {
	Enabled         bool `json:"enabled,omitempty"`
	SampleThreshold int  `json:"sample_threshold,omitempty"`
	MaxRows         int  `json:"max_rows,omitempty"`

	// ModeV2 turns on customer-facing cluster request logs: served rows are
	// UNSAMPLED, blocked/rate-limited/challenge requests are logged with a
	// disposition (non-served rows sampled via BlockedSampleThreshold), and
	// each row carries the extra wire fields (ts_ms, machine_id, machine_seq,
	// disposition, host). Emitted by the Phoenix config generator only for
	// new-enough images, so old configs (ModeV2 false) stay byte-identical.
	ModeV2 bool `json:"mode_v2,omitempty"`
	// BlockedSampleThreshold is the per-window emit count above which
	// NON-served rows sample under load (mode_v2 only). <=0 → default 2000.
	// Served rows ignore this entirely (unsampled).
	BlockedSampleThreshold int `json:"blocked_sample_threshold,omitempty"`
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
	MachineIDValue string `json:"machine_id,omitempty"`

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

	// L4 per-IP tracking lives under one mutex separate from the L4 SNI
	// mutex above. Same handler tick updates both — the L4 SNI path was
	// kept on its own mutex to preserve Phase 1 behaviour under load and
	// because the SNI map (size ~ vhost count) and the per-IP structures
	// (size ~ unique-attacker count) tend to grow on different traffic
	// shapes. Splitting locks lets each path stay tight.
	//
	// All four per-IP structures share l4IpMu so reads at flush see a
	// consistent snapshot (the flush would otherwise interleave a TopK
	// snapshot with a stale prefix map snapshot).
	l4IpMu               sync.Mutex
	l4IpTopk             *topk.Sketch        // heavy-hitter IPs; nil until provisioned
	l4IpSampled          map[string]struct{} // sampled IPs (key: canonical IP string)
	l4IpPrefix           map[string]uint64   // per-(prefix, prefix_len) counters
	l4IpSni              map[string]uint64   // per-(IP, SNI, outcome) counters
	l4IpSniPerIp         map[string]uint16   // distinct-SNI count per IP (cap = maxSnisPerIp)
	l4IpOverflowLogMu    sync.Mutex          // throttles per-IP overflow log
	l4IpOverflowLoggedAt time.Time

	// Challenge attempts. Counter map keyed by (vhost, ip, outcome) — the
	// PoW-challenge handler sets an `apx_challenge_outcome` request var and
	// the StatsHandler records one increment per request that carries it.
	// Single mutexed map (no sharding), mirroring the L4 SNI track:
	// cardinality is low (bounded by the cluster's vhost × attacker-IP
	// fan-out) and the record rate is far below HTTP-request rates, so a
	// single mutex doesn't contend meaningfully. The minute is stamped at
	// drain/encode time (flush minute), so the key carries no ts field.
	challengeMu       sync.Mutex
	challengeMap      map[challengeAttemptKey]uint64
	challengeOverflow uint64 // new keys dropped because the map was at challengeMaxKeys

	// Edge Verify attempts. Counter map keyed by (vhost, path_bucket,
	// outcome) — the Edge Verify edge handler sets an `apx_verify_outcome`
	// request var and the StatsHandler records one increment per request
	// that carries it. Same single-mutexed-map shape as the challenge track
	// (low cardinality, sub-request-rate record rate). The minute is stamped
	// at drain/encode time (flush minute), so the key carries no ts field.
	edgeVerifyMu       sync.Mutex
	edgeVerifyMap      map[edgeVerifyAttemptKey]uint64
	edgeVerifyOverflow uint64 // new keys dropped because the map was at edgeVerifyMaxKeys

	// Fingerprint maps: (ja3, ja4, outcome) traffic and (ja4, ip) join.
	// Both share a single mutex (fpMu) — cardinality is low (bounded by
	// FingerprintMaxKeys/FingerprintIpMaxKeys), so one lock is fine.
	fpMu         sync.Mutex
	fpMap        map[fingerprintKey]*fingerprintCounter
	fpIpMap      map[fingerprintIpKey]*fingerprintCounter
	fpOverflow   uint64 // dropped distinct (ja3,ja4,outcome) keys at cap
	fpIpOverflow uint64 // dropped distinct (ja4,ip) keys at cap

	// Coraza WAF detections. Unlike the fingerprint track (which
	// AGGREGATES into a counter map), detections are RAW per-(request,
	// rule) events — each fired rule on each request is its own row. The
	// store is therefore a capped append-only SLICE, drained at flush.
	// Overflow drops the new event and counts it (matching the
	// fingerprint overflow accounting, but for a slice not a counter map).
	corazaMu            sync.Mutex
	corazaEvents        []corazaDetection
	corazaOverflow      uint64 // dropped events (slice at cap, or governor reject)
	corazaReservedBytes int    // governor bytes reserved by corazaEvents; released at snapshot

	// memGov byte-bounds the two byte-heavy drainable buffers
	// (request_events + corazaEvents) to fit the machine's detected RAM.
	// Built once at Provision; its RSS cache refreshes on a goroutine
	// started by Start. nil only in tests that bypass Provision.
	memGov *memGovernor

	// requestEvents accumulates raw per-(served)-request analytics rows. nil
	// disables the track — RecordRequestEvent becomes a no-op with no
	// allocation. Built at Provision only when ingest.request_events.enabled.
	requestEvents *requestEventRecorder

	// reqEventsModeV2 mirrors ingest.request_events.mode_v2, resolved at
	// Provision. Gates the handler's disposition/host/unsampled-served path.
	reqEventsModeV2 bool

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
	// fingerprintMaxKeys / fingerprintIpMaxKeys are the per-minute caps
	// on distinct keys in the two fingerprint maps. 0 disables the
	// respective track; RecordFingerprint is a no-op per map when 0.
	fingerprintMaxKeys   int
	fingerprintIpMaxKeys int
	// corazaMaxEvents caps the raw detection slice per flush window.
	// Always non-zero after Provision (defaults to CorazaMaxEventsDefault).
	corazaMaxEvents int
}

// CaddyModule registers the app at root ID "apx_stats".
func (*StatsApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "apx_stats",
		New: func() caddy.Module { return new(StatsApp) },
	}
}

// Provision validates config, resolves the shared-secret bearer token
// (ingest.auth_token from the config blob first, AuthEnvVar fallback),
// builds the HTTP client, and initializes the counter map. Called by
// Caddy before Start. The secret is plaintext bearer auth — no HMAC,
// no replay protection — see IngestConfig.AuthToken / AuthEnvVar.
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

	// auth_token from the config blob wins over the env var — same
	// rotation story as hash_salt: config regen, no machine restart.
	if a.Ingest.AuthToken != "" {
		a.secret = a.Ingest.AuthToken
	} else {
		envVar := a.Ingest.AuthEnvVar
		if envVar == "" {
			envVar = "APX_INTERNAL_KEY"
		}
		a.secret = os.Getenv(envVar)
		if a.secret == "" {
			return fmt.Errorf("apx_stats app: %s env var is empty", envVar)
		}
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
		// Fingerprint caps: same convention as l4SniMaxKeys — no default
		// fallback, 0 means "disabled". The control plane sets these
		// explicitly via fingerprint_max_keys / fingerprint_ip_max_keys.
		fingerprintMaxKeys:   a.Ingest.FingerprintMaxKeys,
		fingerprintIpMaxKeys: a.Ingest.FingerprintIpMaxKeys,
		// Coraza detection slice cap: unlike the fingerprint caps, 0 does
		// NOT disable — it falls back to the default. Recording is gated by
		// the WAF config selecting the apx_stats audit writer, not by this.
		corazaMaxEvents: intDefault(a.Ingest.CorazaMaxEvents, CorazaMaxEventsDefault),
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
	a.challengeMap = make(map[challengeAttemptKey]uint64)
	a.edgeVerifyMap = make(map[edgeVerifyAttemptKey]uint64)

	// Memory governor: self-sized from the machine's RAM detected at
	// runtime (the autoscaler resizes machines per-machine, so config-gen
	// can't know it). Byte-bounds the request_events + coraza buffers.
	totalRAM := clampTotalRAM(detectTotalRAM())
	a.memGov = newMemGovernor(totalRAM, readProcessRSS, a.logger)
	a.logger.Info("apx_stats: memory governor sized",
		zap.Uint64("total_ram_bytes", totalRAM),
		zap.Uint64("buffer_share_budget_bytes", a.memGov.shareBudget),
		zap.Uint64("rss_ceiling_bytes", a.memGov.rssCeiling))

	// request_events recorder: built only when the track is explicitly
	// enabled. SampleThreshold passes through as-is (<=0 → never sample);
	// MaxRows defaults to 200_000. Otherwise left nil → RecordRequestEvent
	// no-ops. ModeV2 builds the v2 recorder instead (unsampled served rows,
	// disposition-sampled non-served rows) and resolves reqEventsModeV2.
	if a.Ingest.RequestEvents != nil && a.Ingest.RequestEvents.Enabled {
		if a.Ingest.RequestEvents.ModeV2 {
			a.reqEventsModeV2 = true
			a.requestEvents = newRequestEventRecorderV2(
				intDefault(a.Ingest.RequestEvents.MaxRows, 200_000),
				intDefault(a.Ingest.RequestEvents.BlockedSampleThreshold, 2000),
				a.memGov,
			)
		} else {
			a.requestEvents = newRequestEventRecorder(
				intDefault(a.Ingest.RequestEvents.MaxRows, 200_000),
				a.Ingest.RequestEvents.SampleThreshold,
				a.memGov,
			)
		}
	}
	a.initL4IpState()
	if a.cfg.fingerprintMaxKeys > 0 {
		a.fpMap = make(map[fingerprintKey]*fingerprintCounter)
	}
	if a.cfg.fingerprintIpMaxKeys > 0 {
		a.fpIpMap = make(map[fingerprintIpKey]*fingerprintCounter)
	}
	a.stopCh = make(chan struct{})

	// Publish this app to the global Coraza audit-log writer. The writer
	// is registered by a package init() with no app handle, so it loads
	// the live app from here. Set last, after all state is initialized.
	corazaApp.Store(a)
	return nil
}

// initL4IpState builds the four per-IP tracking structures. Split out
// so tests + Provision share the same construction logic, and so the
// post-flush reset can reuse it.
func (a *StatsApp) initL4IpState() {
	a.l4IpTopk = topk.New(topkSize)
	a.l4IpSampled = make(map[string]struct{})
	a.l4IpPrefix = make(map[string]uint64)
	a.l4IpSni = make(map[string]uint64)
	a.l4IpSniPerIp = make(map[string]uint16)
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

// Start launches the periodic flush goroutine and the governor's RSS
// refresher (a ~µs /proc/self/statm read per second).
func (a *StatsApp) Start() error {
	a.wg.Add(1)
	go a.flushLoop()
	if a.memGov != nil {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.memGov.refreshLoop(a.stopCh)
		}()
	}
	return nil
}

// Stop signals the flush goroutine to drain once more and exit.
func (a *StatsApp) Stop() error {
	// Detach from the Coraza audit-log writer first so in-flight Write
	// calls no-op rather than record into an app that's draining. Only
	// clear if we're still the published app (a hot-reload may have
	// already swapped in the replacement app's pointer at its Provision).
	corazaApp.CompareAndSwap(a, nil)
	a.stopOnce.Do(func() {
		close(a.stopCh)
		// After the old config drains (grace_period is 1s), return the freed
		// WAF/ruleset pages to the OS instead of waiting for kernel pressure.
		// Inside stopOnce so a repeated Stop on this app can't keep pushing
		// the call out; rapid reloads still coalesce across app instances
		// (separate stopOnce) via the package-level debounce timer.
		scheduleFreeOSMemory(10 * time.Second)
	})
	a.wg.Wait()
	return nil
}

// ProxyServerID exposes the cluster id to handlers.
func (a *StatsApp) ProxyServerID() uint32 { return a.ProxyServerIDValue }

// MachineID exposes the configured machine identifier to handlers. May be "".
func (a *StatsApp) MachineID() string { return a.MachineIDValue }

// RequestEventsModeV2 reports whether the request_events track is in
// mode_v2. Resolved at Provision (G5 wiring); false by default.
func (a *StatsApp) RequestEventsModeV2() bool { return a.reqEventsModeV2 }

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

// timeNowUnixMin returns the current Unix time truncated to the minute.
// Used by RecordL4Sni, RecordFingerprint, and their tests to pin minute
// buckets deterministically.
func timeNowUnixMin() uint32 { return uint32(time.Now().Unix() / 60) }

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
	// Bound the key width BEFORE the lookup so lookups and stored keys
	// agree: RFC 6066 caps host_name at 255 bytes, but a hand-rolled
	// ClientHello can claim up to 64KB, and this map is count-capped, not
	// byte-accounted. Copy-free under the cap.
	sni = truncateBytes(sni, l4SniMaxBytes)

	if a.logger != nil {
		a.logger.Debug("apx_stats: RecordL4Sni",
			zap.String("sni", sni),
			zap.Int("cap", a.cfg.l4SniMaxKeys))
	}

	k := L4SniKey{
		TsUnixMin: timeNowUnixMin(),
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

	// First retention of this SNI: own the key string before it enters
	// the long-lived (flush-window) map. The l4tls parser hands us a
	// fresh allocation today, but that provenance lives in the caddy-l4
	// fork — clone-on-insert (new keys only; increments above stay
	// alloc-free) makes the map immune to a fork change reintroducing a
	// shared backing.
	k.SNI = strings.Clone(sni)
	a.l4SniMap[k] = &l4SniCounter{ConnectionCount: 1}
}

// RecordRequestEvent feeds one raw per-(served)-request row into the
// request_events recorder. Called once per served request from the
// StatsHandler (see handler.record) — the served-only filter is applied at
// the call site. nil recorder (track off) → no-op, no allocation. The
// recorder stamps SampleRate and applies the sample-under-load + cap.
func (a *StatsApp) RecordRequestEvent(row requestEventRow) {
	if a.requestEvents == nil {
		return
	}
	a.requestEvents.record(row)
}

// RecordChallengeAttempt increments the challenge-attempt counter for the
// given (vhost, ip, outcome) key. Called once per request whose
// `apx_challenge_outcome` var is set, from the StatsHandler. Nil-safe —
// no-op (and no allocation) when the map hasn't been initialized.
//
// Single mutexed map, mirroring the L4 SNI track. The minute is stamped
// at drain time, so the key carries no ts dimension and same-minute
// (vhost, ip, outcome) tuples merge into one row. New keys past
// challengeMaxKeys are dropped + counted; existing keys keep counting.
func (a *StatsApp) RecordChallengeAttempt(key challengeAttemptKey) {
	a.challengeMu.Lock()
	defer a.challengeMu.Unlock()
	if a.challengeMap == nil {
		return
	}
	if _, ok := a.challengeMap[key]; !ok && len(a.challengeMap) >= challengeMaxKeys {
		a.challengeOverflow++
		metricChallengeOverflows.Inc()
		return
	}
	// Own every key string before it enters the long-lived (flush-window)
	// map. The caller hands us slices of request-owned backings — vhost is
	// a SplitHostPort slice of r.Host (itself possibly a slice of the full
	// request line for absolute-form URIs), outcome is another module's
	// request var — and retaining them would pin the parent allocations.
	// Cloned on EVERY call, not just inserts: `m[key]++` is a map
	// assignment, and the runtime re-stores string-containing keys on
	// every assignment (needkeyupdate), so a clone-on-insert would be
	// silently undone by the next increment. Unlike the pointer-valued
	// SNI/fingerprint maps there is no assignment-free increment here;
	// three small clones per challenge attempt is acceptable.
	key.vhost = strings.Clone(key.vhost)
	key.ip = strings.Clone(key.ip)
	key.outcome = strings.Clone(key.outcome)
	a.challengeMap[key]++
}

// challengeSnapshot atomically swaps the in-memory challenge-attempt map
// and returns the previous contents. Returns nil when empty so flushOnce
// can cheaply skip the track. Mirrors l4SniSnapshot.
func (a *StatsApp) challengeSnapshot() map[challengeAttemptKey]uint64 {
	a.challengeMu.Lock()
	defer a.challengeMu.Unlock()
	if len(a.challengeMap) == 0 {
		return nil
	}
	snap := a.challengeMap
	a.challengeMap = make(map[challengeAttemptKey]uint64)
	return snap
}

// RecordEdgeVerifyAttempt increments the edge-verify-attempt
// counter for the given (vhost, path_bucket, outcome) key. Called once per
// request whose `apx_verify_outcome` var is set, from the StatsHandler.
// Nil-safe — no-op (and no allocation) when the map hasn't been
// initialized.
//
// Single mutexed map, mirroring the challenge track. The minute is stamped
// at drain time, so the key carries no ts dimension and same-minute
// (vhost, path_bucket, outcome) tuples merge into one row. New keys past
// edgeVerifyMaxKeys are dropped + counted; existing keys keep counting.
func (a *StatsApp) RecordEdgeVerifyAttempt(key edgeVerifyAttemptKey) {
	a.edgeVerifyMu.Lock()
	defer a.edgeVerifyMu.Unlock()
	if a.edgeVerifyMap == nil {
		return
	}
	if _, ok := a.edgeVerifyMap[key]; !ok && len(a.edgeVerifyMap) >= edgeVerifyMaxKeys {
		a.edgeVerifyOverflow++
		metricEdgeVerifyOverflows.Inc()
		return
	}
	// Own every key string before it enters the long-lived (flush-window)
	// map. The caller hands us slices of request-owned backings — vhost is a
	// SplitHostPort slice of r.Host, path_bucket is derived from r.URL.Path,
	// outcome is another module's request var — and retaining them would pin
	// the parent allocations. Cloned on EVERY call, not just inserts: `m[key]++`
	// re-stores the string-containing key (needkeyupdate), so a clone-on-insert
	// would be silently undone by the next increment. Mirrors
	// RecordChallengeAttempt.
	key.vhost = strings.Clone(key.vhost)
	key.pathBucket = strings.Clone(key.pathBucket)
	key.outcome = strings.Clone(key.outcome)
	a.edgeVerifyMap[key]++
}

// edgeVerifySnapshot atomically swaps the in-memory edge-verify-attempt map
// and returns the previous contents. Returns nil when empty so flushOnce
// can cheaply skip the track. Mirrors challengeSnapshot.
func (a *StatsApp) edgeVerifySnapshot() map[edgeVerifyAttemptKey]uint64 {
	a.edgeVerifyMu.Lock()
	defer a.edgeVerifyMu.Unlock()
	if len(a.edgeVerifyMap) == 0 {
		return nil
	}
	snap := a.edgeVerifyMap
	a.edgeVerifyMap = make(map[edgeVerifyAttemptKey]uint64)
	return snap
}

// RecordL4Ip updates the four per-IP tracking structures for one
// accepted L4 connection. Called from the same handler tick as
// RecordL4Sni — ip is the canonical post-PROXY-protocol client IP
// pulled from cx.RemoteAddr().
//
// Empty / unparseable IPs are dropped silently — they indicate a
// misconfigured route (handler wired before the proxy_protocol
// matcher) and shouldn't pollute the per-IP signal with synthetic
// rows. The Phase 1 SNI map already captures the "connection accepted
// but no SNI/IP info" case via the L4SniEmptySNI sentinel.
//
// Gated by the same `l4SniMaxKeys > 0` check as RecordL4Sni — the
// per-IP track and the per-SNI track ship together (or not at all).
// No separate config knob per Phase 2 spec.
func (a *StatsApp) RecordL4Ip(ip, sni string) {
	if a.cfg.l4SniMaxKeys <= 0 {
		return
	}
	if ip == "" {
		return
	}
	// Canonicalize at entry so the same logical IP keys consistently
	// across TopK, sampled set, prefix map, and (IP, SNI) breakdown.
	// Unparseable inputs drop silently — caller is L4Handler, which
	// already canonicalizes from cx.RemoteAddr(), so this is mostly
	// belt-and-braces.
	canonical, prefix, prefixLen, ok := canonicalIPAndPrefix(ip)
	if !ok {
		return
	}
	if sni == "" {
		sni = L4SniEmptySNI
	}
	// Same width bound as RecordL4Sni: the (IP, SNI, outcome) composite
	// keys are built fresh but EMBED the SNI, so an unbounded junk SNI
	// would balloon the count-capped map's resident bytes.
	sni = truncateBytes(sni, l4SniMaxBytes)

	a.l4IpMu.Lock()
	defer a.l4IpMu.Unlock()

	// TopK heavy-hitter sketch: always update. CMS over-counts by
	// bounded epsilon but never under-counts — fine for threshold-
	// based auto-block decisions downstream.
	if a.l4IpTopk != nil {
		a.l4IpTopk.Incr(canonical)
	}

	// Sampled-IPs set: hash-based 1-in-N sampling, deterministic per
	// IP so the same IP across adjacent minutes lands the same way.
	if sampleIP(canonical) {
		a.l4IpSampled[canonical] = struct{}{}
	}

	// Prefix counter. Computed at insert via canonicalIPAndPrefix —
	// cheap and keeps the key compact.
	pk := l4IpPrefixKeyString(prefix, prefixLen)
	if _, exists := a.l4IpPrefix[pk]; exists || len(a.l4IpPrefix) < ipPrefixMapCap {
		a.l4IpPrefix[pk]++
	} else {
		a.maybeLogL4IpOverflow("prefix")
	}

	// (IP, SNI, outcome) breakdown. When an IP exceeds maxSnisPerIp
	// distinct SNIs, fold further SNIs into the per-IP overflow
	// sentinel — keeps the (IP, outcome) signal intact while bounding
	// the map's per-IP fan-out.
	outcome := L4IpOutcomeAllowed
	effectiveSni := sni
	count := a.l4IpSniPerIp[canonical]
	primaryKey := l4IpSniKeyString(canonical, sni, outcome)
	if _, exists := a.l4IpSni[primaryKey]; !exists {
		if count >= maxSnisPerIp {
			// Per-IP cap hit. Fold into the overflow sentinel.
			effectiveSni = L4IpOverflowSNI
		} else {
			// New (IP, SNI) under the per-IP cap.
			a.l4IpSniPerIp[canonical] = count + 1
		}
	}

	key := primaryKey
	if effectiveSni != sni {
		key = l4IpSniKeyString(canonical, effectiveSni, outcome)
	}

	if _, exists := a.l4IpSni[key]; exists || len(a.l4IpSni) < ipSniMapCap {
		a.l4IpSni[key]++
	} else {
		a.maybeLogL4IpOverflow("ip_sni")
	}
}

// recordFingerprintMaps writes the (ja3, ja4, outcome) and (ja4, ip) rows.
// ja3 may be the empty-JA3 sentinel when the caller has no JA3 available.
//
// Outcome is always FingerprintOutcomeAllowed in v1 (D1). Empty ja4 or ip
// are dropped per-map. Caps are enforced at insert; new keys past the cap
// are dropped + counted in the overflow metric (NO sentinel row).
func (a *StatsApp) recordFingerprintMaps(ja3, ja4, ip string) {
	tsMin := timeNowUnixMin()

	// --- (ja3, ja4, outcome) traffic map ---
	if a.cfg.fingerprintMaxKeys > 0 && ja4 != "" {
		k := fingerprintKey{TsUnixMin: tsMin, JA3: ja3, JA4: ja4, Outcome: FingerprintOutcomeAllowed}
		a.fpMu.Lock()
		if c, ok := a.fpMap[k]; ok {
			c.ConnectionCount++
		} else if len(a.fpMap) >= a.cfg.fingerprintMaxKeys {
			a.fpOverflow++
			metricFingerprintOverflows.Inc()
		} else {
			// First retention: own the key strings before they enter the
			// long-lived map. ja3/ja4 are fixed-width hashes built by the
			// caddy-l4 fork (fresh today), but their provenance is outside
			// this repo — clone-on-insert (new keys only) keeps the map
			// immune to a fork change sharing a larger backing.
			k.JA3 = strings.Clone(ja3)
			k.JA4 = strings.Clone(ja4)
			a.fpMap[k] = &fingerprintCounter{ConnectionCount: 1}
		}
		a.fpMu.Unlock()
	}

	// --- (ja4, ip) join map ---
	if a.cfg.fingerprintIpMaxKeys > 0 && ja4 != "" && ip != "" {
		k := fingerprintIpKey{TsUnixMin: tsMin, JA4: ja4, IP: ip}
		a.fpMu.Lock()
		if c, ok := a.fpIpMap[k]; ok {
			c.ConnectionCount++
		} else if len(a.fpIpMap) >= a.cfg.fingerprintIpMaxKeys {
			a.fpIpOverflow++
			metricFingerprintIpOverflows.Inc()
		} else {
			// Same clone-on-insert ownership as the traffic map above.
			k.JA4 = strings.Clone(ja4)
			k.IP = strings.Clone(ip)
			a.fpIpMap[k] = &fingerprintCounter{ConnectionCount: 1}
		}
		a.fpMu.Unlock()
	}
}

// RecordFingerprint counts one accepted L4 TLS connection into both
// fingerprint maps: (ja3, ja4, outcome) and (ja4, ip). Called per
// connection from the FingerprintHandler hot path.
func (a *StatsApp) RecordFingerprint(ja3, ja4, ip string) {
	if ja3 == "" || ja4 == "" {
		return
	}
	a.recordFingerprintMaps(ja3, ja4, ip)
}

// RecordJA4 records an observation with no JA3 — the caddytls path cannot
// produce one, because crypto/tls does not expose the legacy client version or
// compression methods. The JA3 column carries EmptyJA3Sentinel so these rows
// are distinguishable downstream from genuine JA3+JA4 observations.
func (a *StatsApp) RecordJA4(ja4, ip string) {
	if ja4 == "" {
		return
	}
	a.recordFingerprintMaps(EmptyJA3Sentinel, ja4, ip)
}

// maybeLogL4IpOverflow throttles per-IP overflow log lines — only one
// log per minute per overflow kind, so an adversarial workload can't
// flood the log even when both maps simultaneously cap out.
func (a *StatsApp) maybeLogL4IpOverflow(kind string) {
	now := time.Now()

	a.l4IpOverflowLogMu.Lock()
	if !a.l4IpOverflowLoggedAt.IsZero() && now.Sub(a.l4IpOverflowLoggedAt) < time.Minute {
		a.l4IpOverflowLogMu.Unlock()
		return
	}
	a.l4IpOverflowLoggedAt = now
	a.l4IpOverflowLogMu.Unlock()

	if a.logger != nil {
		a.logger.Warn("apx_stats: per-IP map at cap — dropping new keys",
			zap.String("map", kind),
			zap.Int("ip_prefix_cap", ipPrefixMapCap),
			zap.Int("ip_sni_cap", ipSniMapCap))
	}
}

// l4IpSnapshot atomically captures all four per-IP structures and
// resets them. Mirrors l4SniSnapshot — one critical section so the
// shipped rows are a consistent point-in-time view.
type l4IpSnap struct {
	topkRows []topkRow
	sampled  map[string]struct{}
	prefix   map[string]uint64
	ipSni    map[string]uint64
}

type topkRow struct {
	IP    string
	Count uint64
}

func (a *StatsApp) l4IpSnapshot() l4IpSnap {
	a.l4IpMu.Lock()
	defer a.l4IpMu.Unlock()

	var snap l4IpSnap
	if a.l4IpTopk != nil {
		sorted := a.l4IpTopk.SortedSlice()
		if len(sorted) > 0 {
			snap.topkRows = make([]topkRow, 0, len(sorted))
			for _, it := range sorted {
				if it.Count == 0 {
					continue
				}
				snap.topkRows = append(snap.topkRows, topkRow{IP: it.Item, Count: uint64(it.Count)})
			}
		}
		a.l4IpTopk.Reset()
	}

	snap.sampled = a.l4IpSampled
	snap.prefix = a.l4IpPrefix
	snap.ipSni = a.l4IpSni

	a.l4IpSampled = make(map[string]struct{})
	a.l4IpPrefix = make(map[string]uint64)
	a.l4IpSni = make(map[string]uint64)
	a.l4IpSniPerIp = make(map[string]uint16)

	return snap
}

// l4IpSnapshot variants below are convenience-wrappers used by tests +
// flushOnce. The flush emits four NDJSON `_type` row kinds:
// l4_ip_topk, l4_ip_uniques_raw, l4_ip_prefix, l4_ip_sni — see
// encoders below.

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

// fingerprintSnapshot atomically takes and resets the (ja3,ja4,outcome)
// map. Unlike drainL4SniRows it keeps EVERY key (count >= 1): the 3d
// auto-block worker uses threshold=1, so a single known-bad observation
// must ship.
func (a *StatsApp) fingerprintSnapshot() map[fingerprintKey]*fingerprintCounter {
	a.fpMu.Lock()
	defer a.fpMu.Unlock()
	if len(a.fpMap) == 0 {
		return nil
	}
	out := a.fpMap
	a.fpMap = make(map[fingerprintKey]*fingerprintCounter)
	return out
}

// fingerprintIpSnapshot atomically takes and resets the (ja4,ip) map,
// keeping every key (count >= 1) — same rationale as fingerprintSnapshot.
func (a *StatsApp) fingerprintIpSnapshot() map[fingerprintIpKey]*fingerprintCounter {
	a.fpMu.Lock()
	defer a.fpMu.Unlock()
	if len(a.fpIpMap) == 0 {
		return nil
	}
	out := a.fpIpMap
	a.fpIpMap = make(map[fingerprintIpKey]*fingerprintCounter)
	return out
}

// RecordCorazaDetection appends one raw per-(request, rule) WAF detection
// event to the capped slice. Called by the Coraza audit-log writer once
// per fired rule per transaction. NOT aggregated — every call adds a row.
// At the count cap OR when the memory governor rejects the event's bytes,
// the event is dropped and counted (corazaOverflow + metric). Hard drop,
// no sampling: there is no sample_rate on the coraza wire format for
// Phoenix to upscale, and a deterministic keep-until-full preserves the
// earliest (strongest) signal of a window.
func (a *StatsApp) RecordCorazaDetection(ev corazaDetection) {
	a.corazaMu.Lock()
	if a.cfg.corazaMaxEvents > 0 && len(a.corazaEvents) >= a.cfg.corazaMaxEvents {
		a.corazaOverflow++
		a.corazaMu.Unlock()
		metricCorazaOverflows.Inc()
		return
	}
	n := corazaDetectionBytes(&ev)
	if a.memGov != nil && !a.memGov.tryReserve(n) {
		a.corazaOverflow++
		a.corazaMu.Unlock()
		metricCorazaOverflows.Inc()
		return
	}
	a.corazaReservedBytes += n
	a.corazaEvents = append(a.corazaEvents, ev)
	a.corazaMu.Unlock()
}

// corazaSnapshot atomically takes and resets the detection slice,
// releasing the window's governor reservation. Returns nil when empty so
// flushOnce can cheaply skip the track. The returned slice is owned by
// the caller (the app starts a fresh one).
func (a *StatsApp) corazaSnapshot() []corazaDetection {
	a.corazaMu.Lock()
	defer a.corazaMu.Unlock()
	if a.memGov != nil && a.corazaReservedBytes > 0 {
		a.memGov.release(a.corazaReservedBytes)
	}
	a.corazaReservedBytes = 0
	if len(a.corazaEvents) == 0 {
		return nil
	}
	out := a.corazaEvents
	a.corazaEvents = nil
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
	l4IpSnap := a.l4IpSnapshot()
	fpSnap := a.fingerprintSnapshot()
	fpIpSnap := a.fingerprintIpSnapshot()
	corazaSnap := a.corazaSnapshot()
	challengeSnap := a.challengeSnapshot()
	edgeVerifySnap := a.edgeVerifySnapshot()
	flushTs := uint32(time.Now().Unix() / 60)

	// request_events: flat drain. reqEventOverflow is observability-only here
	// (no breaker — the recorder samples under load on its own).
	var reqEventRows []requestEventRow
	var reqEventOverflow uint64
	if a.requestEvents != nil {
		reqEventRows, reqEventOverflow = a.requestEvents.drain()
	}

	if a.logger != nil {
		a.logger.Debug("apx_stats: flushOnce summary",
			zap.Int("http_counter_rows", len(snap)),
			zap.Int("uniques_rows", len(uniqSnap)),
			zap.Int("l4_sni_rows_after_filter", len(l4SniSnap)),
			zap.Int("l4_ip_topk_rows", len(l4IpSnap.topkRows)),
			zap.Int("l4_ip_uniques_raw_rows", len(l4IpSnap.sampled)),
			zap.Int("l4_ip_prefix_rows", len(l4IpSnap.prefix)),
			zap.Int("l4_ip_sni_rows", len(l4IpSnap.ipSni)),
			zap.Int("l4_fingerprint_rows", len(fpSnap)),
			zap.Int("l4_fingerprint_ip_rows", len(fpIpSnap)),
			zap.Int("coraza_detection_rows", len(corazaSnap)),
			zap.Int("challenge_attempt_rows", len(challengeSnap)),
			zap.Int("edge_verify_attempt_rows", len(edgeVerifySnap)),
			zap.Int("request_event_rows", len(reqEventRows)),
			zap.Uint64("request_event_overflow", reqEventOverflow))
	}

	if len(snap) == 0 && len(uniqSnap) == 0 && len(l4SniSnap) == 0 &&
		len(l4IpSnap.topkRows) == 0 && len(l4IpSnap.sampled) == 0 &&
		len(l4IpSnap.prefix) == 0 && len(l4IpSnap.ipSni) == 0 &&
		len(fpSnap) == 0 && len(fpIpSnap) == 0 && len(corazaSnap) == 0 &&
		len(challengeSnap) == 0 && len(edgeVerifySnap) == 0 && len(reqEventRows) == 0 {
		return
	}

	rowCount := len(snap) + len(uniqSnap) + len(l4SniSnap) +
		len(l4IpSnap.topkRows) + len(l4IpSnap.sampled) +
		len(l4IpSnap.prefix) + len(l4IpSnap.ipSni) +
		len(fpSnap) + len(fpIpSnap) + len(corazaSnap) +
		len(challengeSnap) + len(edgeVerifySnap) + len(reqEventRows)
	metricBufferSize.Set(float64(rowCount))

	body, err := encodeBatch(a.ProxyServerIDValue, flushTs, snap, uniqSnap, l4SniSnap, l4IpSnap, fpSnap, fpIpSnap, corazaSnap, challengeSnap, edgeVerifySnap, reqEventRows)
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

// proxyServerIDHeader carries the module's cluster id on every ingest
// POST so the control plane can authenticate the per-cluster derived
// key without reading the request body first.
const proxyServerIDHeader = "apx-proxy-server-id"

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
	// forge a batch; rotate ingest.auth_token (config regen) — or
	// APX_INTERNAL_KEY on the env fallback — to invalidate stolen
	// secrets.
	req.Header.Set(a.cfg.authHeader, a.secret)
	// Cluster id alongside the secret lets the control plane verify the
	// per-cluster derived key BEFORE reading the body (pre-body 401).
	req.Header.Set(proxyServerIDHeader, strconv.FormatUint(uint64(a.ProxyServerIDValue), 10))
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
func encodeBatch(proxyServerID uint32, flushTs uint32, snap map[Key]*Counter, uniqSnap map[uniqueKey]map[uint64]struct{}, l4SniSnap map[L4SniKey]*l4SniCounter, ipSnap l4IpSnap, fpSnap map[fingerprintKey]*fingerprintCounter, fpIpSnap map[fingerprintIpKey]*fingerprintCounter, corazaSnap []corazaDetection, challengeSnap map[challengeAttemptKey]uint64, edgeVerifySnap map[edgeVerifyAttemptKey]uint64, reqEventRows []requestEventRow) ([]byte, error) {
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
	for _, r := range ipSnap.topkRows {
		if err := encodeL4IpTopkRow(gz, proxyServerID, flushTs, r.IP, r.Count); err != nil {
			return nil, err
		}
	}
	for ip := range ipSnap.sampled {
		if err := encodeL4IpUniquesRawRow(gz, proxyServerID, flushTs, ip); err != nil {
			return nil, err
		}
	}
	for k, count := range ipSnap.prefix {
		prefix, prefixLen, ok := splitPrefixKey(k)
		if !ok {
			continue
		}
		if err := encodeL4IpPrefixRow(gz, proxyServerID, flushTs, prefix, prefixLen, count); err != nil {
			return nil, err
		}
	}
	for k, count := range ipSnap.ipSni {
		ip, sni, outcome, ok := splitIpSniKey(k)
		if !ok {
			continue
		}
		if err := encodeL4IpSniRow(gz, proxyServerID, flushTs, ip, sni, outcome, count); err != nil {
			return nil, err
		}
	}
	for k, c := range fpSnap {
		// Each fingerprint key carries its own TsUnixMin (record-time
		// minute); pass it, not flushTs, so minute-boundary connections
		// bucket correctly.
		if err := encodeL4FingerprintRow(gz, proxyServerID, k.TsUnixMin, k.JA3, k.JA4, k.Outcome, c.ConnectionCount); err != nil {
			return nil, err
		}
	}
	for k, c := range fpIpSnap {
		if err := encodeL4FingerprintIpRow(gz, proxyServerID, k.TsUnixMin, k.JA4, k.IP, c.ConnectionCount); err != nil {
			return nil, err
		}
	}
	for i := range corazaSnap {
		// Raw per-(request, rule) events — one row each, no aggregation.
		if err := encodeCorazaDetectionRow(gz, corazaSnap[i], proxyServerID); err != nil {
			return nil, err
		}
	}
	for k, count := range challengeSnap {
		// Minute stamped at flush time (the key carries no ts) — same
		// convention as the L4 IP / fingerprint-flushTs tracks.
		if err := encodeChallengeAttemptRow(gz, proxyServerID, flushTs, k, count); err != nil {
			return nil, err
		}
	}
	for k, count := range edgeVerifySnap {
		// Minute stamped at flush time (the key carries no ts) — same
		// convention as the challenge-attempt track.
		if err := encodeEdgeVerifyAttemptRow(gz, proxyServerID, flushTs, k, count); err != nil {
			return nil, err
		}
	}
	for _, row := range reqEventRows {
		if err := encodeRequestEventRow(gz, proxyServerID, row); err != nil {
			return nil, err
		}
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// splitPrefixKey reverses l4IpPrefixKeyString. Returns ok=false on
// malformed inputs (shouldn't happen — they're built by code in this
// package — but defensive).
func splitPrefixKey(k string) (prefix string, prefixLen uint8, ok bool) {
	i := strings.LastIndexByte(k, '|')
	if i < 0 {
		return "", 0, false
	}
	n, err := strconv.ParseUint(k[i+1:], 10, 8)
	if err != nil {
		return "", 0, false
	}
	return k[:i], uint8(n), true
}

// splitIpSniKey reverses l4IpSniKeyString. Same defensive parsing as
// splitPrefixKey. Format: "ip|sni|outcome" — split on the last two
// pipes (outcome and sni are ASCII-clean enum/hostname values, ip
// never contains '|').
func splitIpSniKey(k string) (ip, sni, outcome string, ok bool) {
	last := strings.LastIndexByte(k, '|')
	if last < 0 {
		return "", "", "", false
	}
	prefix := k[:last]
	outcome = k[last+1:]
	mid := strings.LastIndexByte(prefix, '|')
	if mid < 0 {
		return "", "", "", false
	}
	return prefix[:mid], prefix[mid+1:], outcome, true
}

// encodeL4IpTopkRow emits one `_type: "l4_ip_topk"` NDJSON row. Format:
//
//	{"_type":"l4_ip_topk","ts":"...","proxy_server_id":N,"ip":"...","connection_count":N}
func encodeL4IpTopkRow(w *gzip.Writer, ps, ts uint32, ip string, count uint64) error {
	var b strings.Builder
	b.Grow(128)
	b.WriteByte('{')
	writeString(&b, "_type", "l4_ip_topk")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(ts))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "ip", ip)
	b.WriteByte(',')
	writeUint64(&b, "connection_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// encodeL4IpUniquesRawRow emits one `_type: "l4_ip_uniques_raw"` NDJSON
// row — Phoenix builds the HLL approximation by scaling these sampled
// uniques back up by sampleDenom.
//
//	{"_type":"l4_ip_uniques_raw","ts":"...","proxy_server_id":N,"ip":"..."}
func encodeL4IpUniquesRawRow(w *gzip.Writer, ps, ts uint32, ip string) error {
	var b strings.Builder
	b.Grow(96)
	b.WriteByte('{')
	writeString(&b, "_type", "l4_ip_uniques_raw")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(ts))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "ip", ip)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// encodeL4IpPrefixRow emits one `_type: "l4_ip_prefix"` NDJSON row.
//
//	{"_type":"l4_ip_prefix","ts":"...","proxy_server_id":N,"prefix":"...","prefix_len":24|56,"connection_count":N}
func encodeL4IpPrefixRow(w *gzip.Writer, ps, ts uint32, prefix string, prefixLen uint8, count uint64) error {
	var b strings.Builder
	b.Grow(128)
	b.WriteByte('{')
	writeString(&b, "_type", "l4_ip_prefix")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(ts))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "prefix", prefix)
	b.WriteByte(',')
	writeUint16(&b, "prefix_len", uint16(prefixLen))
	b.WriteByte(',')
	writeUint64(&b, "connection_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}

// encodeL4IpSniRow emits one `_type: "l4_ip_sni"` NDJSON row.
//
//	{"_type":"l4_ip_sni","ts":"...","proxy_server_id":N,"ip":"...","sni":"...","outcome":"allowed","connection_count":N}
func encodeL4IpSniRow(w *gzip.Writer, ps, ts uint32, ip, sni, outcome string, count uint64) error {
	var b strings.Builder
	b.Grow(160)
	b.WriteByte('{')
	writeString(&b, "_type", "l4_ip_sni")
	b.WriteByte(',')
	writeString(&b, "ts", formatTs(ts))
	b.WriteByte(',')
	writeUint32(&b, "proxy_server_id", ps)
	b.WriteByte(',')
	writeString(&b, "ip", ip)
	b.WriteByte(',')
	writeString(&b, "sni", sni)
	b.WriteByte(',')
	writeString(&b, "outcome", outcome)
	b.WriteByte(',')
	writeUint64(&b, "connection_count", count)
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
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
