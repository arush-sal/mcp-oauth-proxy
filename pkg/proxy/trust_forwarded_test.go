package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTrustTestProxy builds a forward-auth proxy with the given
// TrustForwardedHeaders toggle and returns its HTTP handler.
func newTrustTestProxy(t *testing.T, trust *bool) http.Handler {
	t.Helper()
	config := &types.Config{
		Mode:                  ModeForwardAuth,
		OAuthClientID:         "test_client_id",
		OAuthClientSecret:     "test_client_secret",
		OAuthAuthorizeURL:     "https://accounts.google.com",
		ScopesSupported:       "openid,profile,email",
		TrustForwardedHeaders: trust,
	}
	p, err := NewOAuthProxy(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p.GetHandler()
}

// newTrustTestProxyViaSetupRoutes builds a forward-auth proxy with the given
// TrustForwardedHeaders toggle and registers it onto a plain http.ServeMux via
// the exported SetupRoutes (NOT GetHandler), exercising the direct-SetupRoutes
// usage path (embedding/middleware mode).
func newTrustTestProxyViaSetupRoutes(t *testing.T, trust *bool) http.Handler {
	t.Helper()
	config := &types.Config{
		Mode:                  ModeForwardAuth,
		OAuthClientID:         "test_client_id",
		OAuthClientSecret:     "test_client_secret",
		OAuthAuthorizeURL:     "https://accounts.google.com",
		ScopesSupported:       "openid,profile,email",
		TrustForwardedHeaders: trust,
	}
	p, err := NewOAuthProxy(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	mux := http.NewServeMux()
	p.SetupRoutes(mux, nil)
	return mux
}

const spoofedBaseURL = "https://spoofed.attacker.example"

// TestTrustForwardedDefaultHonorsSpoof verifies that with no toggle (nil =>
// trust), a spoofed X-Mcp-Oauth-Proxy-URL flows into the protected-resource
// metadata resource field, preserving today's behavior.
func TestTrustForwardedDefaultHonorsSpoof(t *testing.T) {
	handler := newTrustTestProxy(t, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	req.Header.Set("X-Mcp-Oauth-Proxy-URL", spoofedBaseURL)
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), spoofedBaseURL,
		"default (nil/true) must honor spoofed proxy URL header")
}

// TestTrustForwardedDisabledDropsSpoof verifies that with the toggle off, a
// spoofed X-Mcp-Oauth-Proxy-URL is NOT reflected in the metadata resource field.
func TestTrustForwardedDisabledDropsSpoof(t *testing.T) {
	handler := newTrustTestProxy(t, boolPtr(false))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	req.Header.Set("X-Mcp-Oauth-Proxy-URL", spoofedBaseURL)
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), spoofedBaseURL,
		"trust=false must drop spoofed proxy URL header")
}

// TestTrustForwardedDisabledDropsSpoofViaSetupRoutes verifies that the trust
// policy is honored even when routes are registered through the exported
// SetupRoutes directly (without GetHandler). This guards against the trust
// injection living only in the GetHandler wrapper, which direct-SetupRoutes
// callers (embedding/middleware mode) would bypass.
func TestTrustForwardedDisabledDropsSpoofViaSetupRoutes(t *testing.T) {
	handler := newTrustTestProxyViaSetupRoutes(t, boolPtr(false))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	req.Header.Set("X-Mcp-Oauth-Proxy-URL", spoofedBaseURL)
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), spoofedBaseURL,
		"trust=false must drop spoofed proxy URL header even via SetupRoutes")
}
