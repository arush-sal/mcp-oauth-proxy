package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// boolPtr is a small helper for building *bool config values in tests.
func boolPtr(b bool) *bool { return &b }

// newDCRTestProxy builds a forward-auth proxy (no MCP server URL required) with
// the given DCR toggle and returns its HTTP handler.
func newDCRTestProxy(t *testing.T, enableDCR *bool) http.Handler {
	t.Helper()
	config := &types.Config{
		Mode:                            ModeForwardAuth,
		OAuthClientID:                   "test_client_id",
		OAuthClientSecret:               "test_client_secret",
		OAuthAuthorizeURL:               "https://accounts.google.com",
		ScopesSupported:                 "openid,profile,email",
		EnableDynamicClientRegistration: enableDCR,
	}
	p, err := NewOAuthProxy(config)
	if err != nil {
		t.Skipf("Skipping test due to database connection error: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p.GetHandler()
}

const dcrRegisterBody = `{"redirect_uris":["https://client.example.com/callback"],"client_name":"Test Client","token_endpoint_auth_method":"none"}`

// TestDCREnabledByDefault asserts that with no explicit toggle (nil), DCR is on:
// /register registers a client and metadata advertises registration_endpoint.
func TestDCREnabledByDefault(t *testing.T) {
	handler := newDCRTestProxy(t, nil)

	t.Run("RegisterSucceeds", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", strings.NewReader(dcrRegisterBody))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "client_id")
	})

	t.Run("MetadataAdvertisesRegistrationEndpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "registration_endpoint")
	})
}

// TestDCRExplicitlyEnabled mirrors the default but sets the toggle to true.
func TestDCRExplicitlyEnabled(t *testing.T) {
	handler := newDCRTestProxy(t, boolPtr(true))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", strings.NewReader(dcrRegisterBody))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "client_id")

	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "registration_endpoint")
}

// TestDCRDisabled asserts that with the toggle off, /register is rejected with
// 403 + an OAuthError body and metadata omits registration_endpoint.
func TestDCRDisabled(t *testing.T) {
	handler := newDCRTestProxy(t, boolPtr(false))

	t.Run("RegisterForbidden", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", strings.NewReader(dcrRegisterBody))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "error")
		assert.Contains(t, w.Body.String(), "dynamic client registration is disabled")
	})

	t.Run("MetadataOmitsRegistrationEndpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.NotContains(t, body, "registration_endpoint")
		// Sanity: other endpoints are still advertised.
		assert.Contains(t, body, "authorization_endpoint")
	})
}
