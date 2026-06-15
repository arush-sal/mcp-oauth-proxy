package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newExternalBaseURLProxy builds a forward-auth proxy with the given
// EXTERNAL_BASE_URL and trust toggle and returns its HTTP handler.
func newExternalBaseURLProxy(t *testing.T, externalBaseURL string, trust *bool) http.Handler {
	t.Helper()
	config := &types.Config{
		Mode:                  ModeForwardAuth,
		OAuthClientID:         "test_client_id",
		OAuthClientSecret:     "test_client_secret",
		OAuthAuthorizeURL:     "https://accounts.google.com",
		ScopesSupported:       "openid,profile,email",
		ExternalBaseURL:       externalBaseURL,
		TrustForwardedHeaders: trust,
	}
	p, err := NewOAuthProxy(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p.GetHandler()
}

// TestExternalBaseURLIgnoresSpoofedProxyURL verifies that when EXTERNAL_BASE_URL
// is configured, a spoofed X-Mcp-Oauth-Proxy-URL is ignored end-to-end: the
// protected-resource metadata reflects the authoritative external base URL and
// NOT the spoofed value, even with trust enabled.
func TestExternalBaseURLIgnoresSpoofedProxyURL(t *testing.T) {
	const canonical = "https://canonical.example"

	for _, tc := range []struct {
		name  string
		trust *bool
	}{
		{"TrustDefault", nil},
		{"TrustTrue", boolPtr(true)},
		{"TrustFalse", boolPtr(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := newExternalBaseURLProxy(t, canonical, tc.trust)

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
			req.Header.Set("X-Mcp-Oauth-Proxy-URL", spoofedBaseURL)
			handler.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			body := w.Body.String()
			assert.Contains(t, body, canonical,
				"metadata must reflect the authoritative EXTERNAL_BASE_URL")
			assert.NotContains(t, body, spoofedBaseURL,
				"EXTERNAL_BASE_URL set must drop spoofed proxy URL header")
		})
	}
}

// TestNewOAuthProxyRejectsMalformedExternalBaseURL verifies that NewOAuthProxy
// itself validates EXTERNAL_BASE_URL before snapshotting it, so a direct or
// embedding caller that bypasses cmd.validateConfig cannot construct a proxy
// that serves a garbage authoritative base URL.
func TestNewOAuthProxyRejectsMalformedExternalBaseURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		base string
	}{
		{"NoScheme", "canonical.example"},
		{"WithPath", "https://canonical.example/oauth"},
		{"BadScheme", "ftp://canonical.example"},
		{"ControlChar", "https://canonical.example\x7f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &types.Config{
				Mode:              ModeForwardAuth,
				OAuthClientID:     "test_client_id",
				OAuthClientSecret: "test_client_secret",
				OAuthAuthorizeURL: "https://accounts.google.com",
				ScopesSupported:   "openid,profile,email",
				ExternalBaseURL:   tc.base,
			}
			p, err := NewOAuthProxy(config)
			if p != nil {
				t.Cleanup(func() { _ = p.Close() })
			}
			require.Error(t, err, "NewOAuthProxy must reject malformed EXTERNAL_BASE_URL %q", tc.base)
			assert.Nil(t, p, "NewOAuthProxy must not construct a proxy with a malformed EXTERNAL_BASE_URL")
		})
	}
}
