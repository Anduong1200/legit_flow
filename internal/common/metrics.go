package common

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RequestsTotal counts all incoming proxy requests.
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "legitflow",
		Name:      "requests_total",
		Help:      "Total number of proxy requests",
	}, []string{"method", "path", "status"})

	// RequestDuration measures request latency in seconds.
	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "legitflow",
		Name:      "request_duration_seconds",
		Help:      "Request duration in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "tier"})

	// DetectionsTotal counts PII/secret detections.
	DetectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "legitflow",
		Name:      "detections_total",
		Help:      "Total PII/secret detections",
	}, []string{"type", "action"})

	// OutputGuardTruncations counts streaming truncation events.
	OutputGuardTruncations = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "legitflow",
		Name:      "output_guard_truncations_total",
		Help:      "Number of streaming responses truncated by output guard",
	})

	// AuditEventsTotal counts audit events by tier.
	AuditEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "legitflow",
		Name:      "audit_events_total",
		Help:      "Total audit events",
	}, []string{"tier"})
)
