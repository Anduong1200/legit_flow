package gateway

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/legitflow/legitflow/internal/common"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsServer serves Prometheus metrics on a separate port.
type MetricsServer struct {
	server *http.Server
}

// NewMetricsServer creates a Prometheus metrics endpoint.
func NewMetricsServer(addr string) *MetricsServer {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return &MetricsServer{
		server: &http.Server{
			Addr:    addr,
			Handler: mux,
		},
	}
}

// Start begins serving metrics.
func (m *MetricsServer) Start() error {
	return m.server.ListenAndServe()
}

// RequestMetricsMiddleware wraps an http.Handler with Prometheus metrics.
func RequestMetricsMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Seconds()
		status := http.StatusText(wrapped.statusCode)

		common.RequestsTotal.WithLabelValues(r.Method, r.URL.Path, status).Inc()
		common.RequestDuration.WithLabelValues(r.Method, "default").Observe(duration)

		logger.Debug("request.complete",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
