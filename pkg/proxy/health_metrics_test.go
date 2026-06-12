package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestProxy(t *testing.T, cfg *types.Config) *OAuthProxy {
	t.Helper()
	if cfg.Mode == "" {
		cfg.Mode = ModeForwardAuth
	}
	if cfg.OAuthClientID == "" {
		cfg.OAuthClientID = "test_client_id"
		cfg.OAuthClientSecret = "test_client_secret"
		cfg.OAuthAuthorizeURL = "https://accounts.google.com"
		cfg.ScopesSupported = "openid,profile,email"
	}
	p, err := NewOAuthProxy(cfg)
	if err != nil {
		t.Skipf("Skipping due to database connection error: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestLivenessDefaultPath(t *testing.T) {
	p := newTestProxy(t, &types.Config{})
	handler := p.GetHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestLivenessCustomPath(t *testing.T) {
	p := newTestProxy(t, &types.Config{HealthPath: "/live"})
	handler := p.GetHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Default path should NOT be mounted when a custom one is set.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	handler.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestHealthBackCompat(t *testing.T) {
	p := newTestProxy(t, &types.Config{})
	handler := p.GetHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestHealthPathEqualsLegacyNoPanic(t *testing.T) {
	// HEALTH_PATH=/health with an empty RoutePrefix makes the configured
	// liveness probe path identical to the legacy "/health" route. Building the
	// handler must NOT panic on a duplicate GET /health registration, and
	// /health must still return a 200 liveness response.
	p := newTestProxy(t, &types.Config{HealthPath: "/health"})

	var handler http.Handler
	require.NotPanics(t, func() {
		handler = p.GetHandler()
	}, "building handler with HEALTH_PATH=/health and empty prefix must not panic")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestDefaultServesLegacyHealthAndHealthz(t *testing.T) {
	// Default config (HealthPath defaults to /healthz) must expose BOTH the
	// legacy /health route and the /healthz probe, plus /readyz.
	p := newTestProxy(t, &types.Config{})
	handler := p.GetHandler()

	for _, path := range []string{"/health", "/healthz", "/readyz"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		handler.ServeHTTP(w, req)
		assert.Equalf(t, http.StatusOK, w.Code, "path %s should be 200", path)
	}
}

func TestReadinessOK(t *testing.T) {
	p := newTestProxy(t, &types.Config{})
	handler := p.GetHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestReadinessDBFailure(t *testing.T) {
	p := newTestProxy(t, &types.Config{ReadyPath: "/ready"})
	// Inject a failing readiness check to simulate an unreachable DB.
	p.readinessPing = func(context.Context) error {
		return errors.New("db down")
	}
	handler := p.GetHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestProbesBypassAuthAndIgnoreRoutePrefix(t *testing.T) {
	// Even with a RoutePrefix set, probes are registered at root and need no token.
	p := newTestProxy(t, &types.Config{RoutePrefix: "/oauth2"})
	handler := p.GetHandler()

	// Liveness/readiness are mounted at ROOT (not under RoutePrefix) and need no
	// token. (/health is the legacy alias and remains prefix-bound by design.)
	for _, path := range []string{"/healthz", "/readyz"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil) // no Authorization header
		handler.ServeHTTP(w, req)
		assert.Equalf(t, http.StatusOK, w.Code, "path %s should be 200 without auth", path)

		// Confirm the probe is NOT mounted under the prefix.
		w = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/oauth2"+path, nil)
		handler.ServeHTTP(w, req)
		assert.NotEqualf(t, http.StatusOK, w.Code, "prefixed %s should not be a probe", "/oauth2"+path)
	}
}

func TestMetricsDisabledByDefault(t *testing.T) {
	// Use a RoutePrefix so the root /metrics path is not swallowed by the
	// catch-all proxy route; with metrics disabled it must be a clean 404.
	p := newTestProxy(t, &types.Config{RoutePrefix: "/oauth2"})
	handler := p.GetHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.NotContains(t, w.Body.String(), "http_requests_total")
}

func TestMetricsEnabledOnMainMux(t *testing.T) {
	p := newTestProxy(t, &types.Config{EnableMetrics: true})
	handler := p.GetHandler()

	// Issue a request to increment the request counter.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Scrape metrics.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "http_requests_total")
	assert.Contains(t, body, "http_request_duration_seconds")
}

func TestMetricsSeparateAddressNotOnMainMux(t *testing.T) {
	p := newTestProxy(t, &types.Config{EnableMetrics: true, MetricsAddress: ":0", RoutePrefix: "/oauth2"})
	handler := p.GetHandler()

	// With a separate address configured, metrics must NOT be on the main mux.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// The separate metrics handler is still available via the proxy method.
	mh := p.MetricsHandler()
	require.NotNil(t, mh)
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mh.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
