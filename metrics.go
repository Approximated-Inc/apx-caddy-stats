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
