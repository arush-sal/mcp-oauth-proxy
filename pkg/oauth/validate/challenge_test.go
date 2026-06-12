package validate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSendUnauthorized_AgentPathEmitsChallenge pins the agent contract: an MCP
// path (or any non-browser UA) gets a 401 carrying the WWW-Authenticate Bearer
// challenge plus the protected-resource metadata pointer, and a JSON body. Never
// a 500, never a redirect.
func TestSendUnauthorized_AgentPathEmitsChallenge(t *testing.T) {
	v := &TokenValidator{mcpPaths: []string{"/mcp"}}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/mcp", nil)
	req.Header.Set("User-Agent", "mcp-agent/1.0")
	rec := httptest.NewRecorder()

	v.sendUnauthorizedResponse(rec, req, "Invalid or expired token")

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	want := `Bearer error="invalid_token", error_description="Invalid or expired token", resource_metadata="https://proxy.example.com/.well-known/oauth-protected-resource/mcp"`
	assert.Equal(t, want, rec.Header().Get("WWW-Authenticate"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_token", body["error"])
	assert.Equal(t, "Invalid or expired token", body["error_description"])
}

// TestSendUnauthorized_NonBrowserNonMCPEmitsChallenge confirms a non-mcp path
// with a non-browser UA still gets the challenge (not the redirect).
func TestSendUnauthorized_NonBrowserNonMCPEmitsChallenge(t *testing.T) {
	v := &TokenValidator{mcpPaths: []string{"/mcp"}}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/sse", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rec := httptest.NewRecorder()

	v.sendUnauthorizedResponse(rec, req, "nope")

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `Bearer error="invalid_token"`)
	assert.Empty(t, rec.Header().Get("X-Redirect-URL"))
}

// TestSendUnauthorized_BrowserPathRedirects pins the existing browser behavior:
// a mozilla UA on a non-mcp path is redirected into the IdP login flow with the
// X-Redirect-URL header set (302). This branch must be preserved unchanged.
func TestSendUnauthorized_BrowserPathRedirects(t *testing.T) {
	store := &fakeTokenStore{}
	v := &TokenValidator{
		db:              store,
		mcpPaths:        []string{"/mcp"},
		provider:        providers.NewGenericProvider("https://accounts.example.com"),
		clientID:        "client-123",
		clientSecret:    "secret-456",
		scopesSupported: []string{"openid", "email"},
	}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/dashboard", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh)")
	rec := httptest.NewRecorder()

	v.sendUnauthorizedResponse(rec, req, "expired")

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("X-Redirect-URL"), "browser path must set X-Redirect-URL")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"), "browser redirect path must not emit a Bearer challenge")
	stateCookie := findResponseCookie(rec.Result().Cookies(), types.OAuthStateCookieName)
	require.NotNil(t, stateCookie, "browser OAuth redirect must bind state to a cookie")
	assert.NotEmpty(t, stateCookie.Value)
}

func findResponseCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
