package apxtrace

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// metricRequestsTotal counts outer-wrapper invocations by outcome.
// Labels:
//   result = "no_header" | "invalid_token" | "active"
var metricRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "apx_trace_requests_total",
		Help: "apx-caddy-trace outer wrapper invocations by result",
	},
	[]string{"result"},
)

// metricEventsEmittedTotal counts events successfully delivered to the sink.
var metricEventsEmittedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "apx_trace_events_emitted_total",
		Help: "apx-caddy-trace events emitted to the event sink",
	},
	[]string{"type"},
)

// metricEventsDropped counts events dropped due to full outbound buffer.
var metricEventsDropped = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_trace_events_dropped_total",
		Help: "apx-caddy-trace events dropped by bounded buffer overflow",
	},
)

// metricEventSinkErrors counts HTTP event-sink delivery errors.
var metricEventSinkErrors = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "apx_trace_event_sink_errors_total",
		Help: "apx-caddy-trace event-sink HTTP delivery errors",
	},
)

// metricEventSinkDuration observes event-sink POST latency in seconds.
var metricEventSinkDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "apx_trace_event_sink_duration_seconds",
		Help:    "apx-caddy-trace event-sink POST latency",
		Buckets: prometheus.ExponentialBuckets(0.0005, 2, 10),
	},
)
