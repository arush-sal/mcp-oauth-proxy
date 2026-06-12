package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTrustClientIPProxy builds a forward-auth proxy with the given
// TrustForwardedHeaders toggle and returns it (not just its handler) so tests
// can exercise the withCORS wrapper that injects the trust context consumed by
// the rate-limit client-IP derivation.
func newTrustClientIPProxy(t *testing.T, trust *bool) *OAuthProxy {
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
	return p
}

// TestTrustForwardedRateLimitClientIP verifies that the rate-limit client IP
// (handlerutils.GetClientIP, read through the context injected by withCORS)
// ignores a spoofed X-Forwarded-For when trust is disabled, so a client cannot
// rotate the per-IP rate-limit key. With trust enabled (default), the forwarded
// header is honored exactly as before.
func TestTrustForwardedRateLimitClientIP(t *testing.T) {
	capture := func(p *OAuthProxy, spoofXFF string) string {
		var captured string
		h := p.withCORS(func(w http.ResponseWriter, r *http.Request) {
			captured = handlerutils.GetClientIP(r)
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest("GET", "/anything", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", spoofXFF)
		h.ServeHTTP(httptest.NewRecorder(), req)
		return captured
	}

	t.Run("Disabled_DropsSpoofedXFF", func(t *testing.T) {
		p := newTrustClientIPProxy(t, boolPtr(false))
		got := capture(p, "203.0.113.7")
		assert.Equal(t, "10.0.0.1", got,
			"trust=false must use RemoteAddr host, not spoofed X-Forwarded-For")
	})

	t.Run("Default_HonorsXFF", func(t *testing.T) {
		p := newTrustClientIPProxy(t, nil) // nil => trust
		got := capture(p, "203.0.113.7")
		assert.Equal(t, "203.0.113.7", got,
			"default (nil/true) must honor X-Forwarded-For")
	})

	t.Run("Enabled_HonorsXFF", func(t *testing.T) {
		p := newTrustClientIPProxy(t, boolPtr(true))
		got := capture(p, "203.0.113.7")
		assert.Equal(t, "203.0.113.7", got,
			"trust=true must honor X-Forwarded-For")
	})
}
