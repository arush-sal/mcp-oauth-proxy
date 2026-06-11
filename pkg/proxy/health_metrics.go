package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsBundle owns a private Prometheus registry and the HTTP instruments. A
// custom (non-default) registry keeps metrics isolated per proxy instance,
// which makes the endpoints testable and avoids duplicate-registration panics
// when several proxies are constructed in one process (e.g. across tests).
type metricsBundle struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// newMetricsBundle builds a fresh registry and registers the HTTP instruments.
//
// Exposed metrics:
//   - http_requests_total{code,method}      counter
//   - http_request_duration_seconds{method} histogram
//
// Go runtime and process collectors are also registered so the endpoint
// exposes standard go_* / process_* metrics.
func newMetricsBundle() *metricsBundle {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	factory := promauto.With(reg)
	requests := factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests handled by the proxy, by response code and method.",
		},
		[]string{"code", "method"},
	)
	duration := factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds, by method.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	return &metricsBundle{
		registry: reg,
		requests: requests,
		duration: duration,
	}
}

// instrument wraps an http.Handler so every request increments the request
// counter (labelled by status code and method) and records its duration.
func (m *metricsBundle) instrument(next http.Handler) http.Handler {
	withDuration := promhttp.InstrumentHandlerDuration(m.duration, next)
	return promhttp.InstrumentHandlerCounter(m.requests, withDuration)
}

// handler returns the Prometheus exposition handler bound to this bundle's
// private registry.
func (m *metricsBundle) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

// MetricsHandler returns the Prometheus metrics HTTP handler bound to this
// proxy's private registry, or nil when metrics are disabled. It is used by the
// cmd layer to serve metrics on a separate listener (METRICS_ADDRESS).
func (p *OAuthProxy) MetricsHandler() http.Handler {
	if p.metrics == nil {
		return nil
	}
	return p.metrics.handler()
}

// HealthMetricsConfig returns the resolved health/metrics policy (defaulted
// paths + the metrics-location decision). The cmd layer uses it to decide
// whether to start a separate metrics listener and at what address/path.
func (p *OAuthProxy) HealthMetricsConfig() types.HealthMetricsConfig {
	return p.healthMetricsCfg
}

// registerHealthMetricsRoutes mounts the liveness, readiness, and (optionally)
// metrics endpoints at the ROOT of the mux using exact paths so they bypass the
// RoutePrefix and never fall into the catch-all proxy route. None are
// rate-limited or token-validated.
func (p *OAuthProxy) registerHealthMetricsRoutes(mux *http.ServeMux) {
	h := p.healthMetricsCfg

	mux.HandleFunc("GET "+h.HealthPath, p.withCORS(p.livenessHandler))
	mux.HandleFunc("GET "+h.ReadyPath, p.withCORS(p.readinessHandler))

	// Metrics on the main mux only when enabled and no separate listener is
	// configured. When MetricsAddress is set the handler lives on its own
	// listener (started by the cmd layer) instead.
	if h.MetricsOnMainMux() && p.metrics != nil {
		mux.Handle("GET "+h.MetricsPath, p.metrics.handler())
	}
}

// livenessHandler is the Kubernetes-style liveness probe. It returns 200
// unconditionally with a small body and performs NO dependency checks: it only
// reports that the process is up and serving.
func (p *OAuthProxy) livenessHandler(w http.ResponseWriter, r *http.Request) {
	handlerutils.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readinessHandler is the Kubernetes-style readiness probe. It checks the
// proxy's critical dependency (the database) via a ping with a short timeout
// and returns 200 when ready or 503 with an error body when not.
func (p *OAuthProxy) readinessHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if p.readinessPing != nil {
		if err := p.readinessPing(ctx); err != nil {
			handlerutils.JSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unavailable",
				"reason": "database not reachable",
			})
			return
		}
	}
	handlerutils.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
