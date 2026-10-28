package apxstats

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// metricRequestsTotal counts handler invocations by classified origin.
//
//	origin = "upstream" | "cluster" | "cluster_proxy_error"
var metricRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "apx_stats_requests_total",
		Help: "apx-caddy-stats handler invocations by origin",
	},
	[]string{"origin"},
)

// metricBufferSize is the row count of the most recently shipped batch.
// Useful as a proxy for hot-key cardinality in the cluster.
var metricBufferSize = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "apx_stats_buffer_size",
		Help: "apx-caddy-stats live counter map size at last flush",
	},
)

// metricBufferOverflow counts new keys dropped because MaxBufferRows
// was hit. Existing keys keep counting; this only fires when the unique
// (vhost,status,method,…) set exceeds the cap inside one flush window.
var metricBufferOverflow = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_stats_buffer_overflow_total",
		Help: "apx-caddy-stats new keys dropped due to MaxBufferRows cap",
	},
)

// metricUniquesOverflow counts unique-hash inserts dropped because
// MaxUniqueHashes was hit. Existing per-(vhost,minute) sets keep their
// already-recorded distinct clients; this only fires when total unique
// hash entries exceeds the cap inside one flush window.
var metricUniquesOverflow = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_stats_uniques_overflow_total",
		Help: "apx-caddy-stats unique hashes dropped due to MaxUniqueHashes cap",
	},
)

// metricShipAttempts counts ingest POST attempts.
//
//	result = "ok" | "transient" | "permanent"
var metricShipAttempts = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "apx_stats_ship_attempts_total",
		Help: "apx-caddy-stats ingest POST attempts",
	},
	[]string{"result"},
)

// metricShipDuration observes ingest POST latency in seconds.
var metricShipDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "apx_stats_ship_duration_seconds",
		Help:    "apx-caddy-stats ingest POST latency",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 12),
	},
)

// metricDroppedRows counts rows dropped after retry exhaustion or
// encoding failure.
var metricDroppedRows = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_stats_dropped_rows_total",
		Help: "apx-caddy-stats rows dropped due to retry exhaustion",
	},
)

// metricStopWait observes how long StatsApp.Stop waited for the final
// batch to ship (capped by ingest.stop_wait_ms).
var metricStopWait = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "apx_stats_stop_wait_seconds",
		Help:    "apx-caddy-stats time Stop waited for the final batch to ship",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	},
)

// metricRetiredShip counts shutdown-phase and retired-HTTP ships.
//
//	result = "ok" | "deadline" | "busy" | "permanent" | "exhausted"
var metricRetiredShip = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "apx_stats_retired_ship_total",
		Help: "apx-caddy-stats ships by stopping or retired generations",
	},
	[]string{"result"},
)

// metricShipQueueDroppedRows counts rows dropped because the ship queue
// was full (the oldest queued batch is dropped).
var metricShipQueueDroppedRows = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_stats_ship_queue_dropped_rows_total",
		Help: "apx-caddy-stats rows dropped from a full ship queue",
	},
)

// metricOverloadLevel is the node's overload level: 0 normal, 1 conserve,
// 2 shed. 0 while overload control is disabled.
var metricOverloadLevel = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "apx_stats_overload_level",
		Help: "apx-caddy-stats node overload level (0 normal, 1 conserve, 2 shed)",
	},
)

// metricOverloadWAFSkips counts WAF evaluations skipped for overload.
//
//	kind = "detect" | "static" | "would_skip"
var metricOverloadWAFSkips = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "apx_stats_overload_waf_skips_total",
		Help: "apx-caddy-stats WAF evaluations skipped (or would be, in observe) for overload",
	},
	[]string{"kind"},
)

// metricFingerprintOverflows counts new (ja3,ja4,outcome) keys dropped
// because the per-minute fingerprint map was at cap.
var metricFingerprintOverflows = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_l4_fingerprint_bounded_map_overflows_total",
		Help: "Distinct (ja3,ja4,outcome) keys dropped because the per-minute fingerprint map was at cap.",
	},
)

// metricFingerprintIpOverflows counts new (ja4,ip) keys dropped
// because the per-minute fingerprint-ip map was at cap.
var metricFingerprintIpOverflows = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_l4_fingerprint_ip_bounded_map_overflows_total",
		Help: "Distinct (ja4,ip) keys dropped because the per-minute fingerprint-ip map was at cap.",
	},
)

// metricChallengeOverflows counts new (vhost, ip, outcome) keys dropped
// because the per-flush challenge-attempt map was at challengeMaxKeys.
var metricChallengeOverflows = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_stats_challenge_map_overflows_total",
		Help: "Distinct (vhost, ip, outcome) keys dropped because the per-flush challenge-attempt map was at cap.",
	},
)

// metricEdgeVerifyOverflows counts new (vhost, path_bucket, outcome) keys
// dropped because the per-flush edge-verify-attempt map was at
// edgeVerifyMaxKeys.
var metricEdgeVerifyOverflows = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_stats_edge_verify_map_overflows_total",
		Help: "Distinct (vhost, path_bucket, outcome) keys dropped because the per-flush edge-verify-attempt map was at cap.",
	},
)

// metricCorazaOverflows counts raw WAF detection events dropped because
// the per-flush-window detection slice was at its cap.
var metricCorazaOverflows = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_coraza_detection_slice_overflows_total",
		Help: "Raw Coraza detection events dropped because the per-flush detection slice was at cap.",
	},
)
