package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/ratelimit"
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

// TestDCRRegisterIsRateLimited proves the /register route is wrapped by the
// per-IP rate limiter (M1 throttle requirement). With the limiter dialed down to
// a single request, the second /register from the same client is throttled with
// 429 before reaching the handler, confirming withRateLimit applies to the
// route. This is a light assertion: it does not exercise the production window.
func TestDCRRegisterIsRateLimited(t *testing.T) {
	config := &types.Config{
		Mode:                            ModeForwardAuth,
		OAuthClientID:                   "test_client_id",
		OAuthClientSecret:               "test_client_secret",
		OAuthAuthorizeURL:               "https://accounts.google.com",
		ScopesSupported:                 "openid,profile,email",
		EnableDynamicClientRegistration: boolPtr(true),
	}
	p, err := NewOAuthProxy(config)
	if err != nil {
		t.Skipf("Skipping test due to database connection error: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	// Replace the limiter with a 1-request-per-window one so the route's
	// withRateLimit wrapper trips on the second request.
	p.rateLimiter = ratelimit.NewRateLimiter(time.Minute, 1)
	handler := p.GetHandler()

	send := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", strings.NewReader(dcrRegisterBody))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.7:5555"
		handler.ServeHTTP(w, req)
		return w
	}

	require.NotEqual(t, http.StatusTooManyRequests, send().Code, "first request must not be throttled")
	require.Equal(t, http.StatusTooManyRequests, send().Code, "second request from same IP must be throttled by withRateLimit")
}

// TestDCRDisabledByDefault asserts that with no explicit toggle (nil), DCR is
// off: /register is forbidden and metadata omits registration_endpoint.
func TestDCRDisabledByDefault(t *testing.T) {
	handler := newDCRTestProxy(t, nil)

	t.Run("RegisterForbidden", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", strings.NewReader(dcrRegisterBody))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	})

	t.Run("MetadataOmitsRegistrationEndpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.NotContains(t, w.Body.String(), "registration_endpoint")
	})
}

// TestDCRExplicitlyEnabled opts into dynamic registration.
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
