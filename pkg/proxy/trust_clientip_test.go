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
// TrustForwardedHeaders toggle and XFF trusted-hop count, and returns it (not
// just its handler) so tests can exercise the withCORS wrapper that injects the
// trust + hop-count context consumed by the rate-limit client-IP derivation.
func newTrustClientIPProxy(t *testing.T, trust *bool, hopCount int) *OAuthProxy {
	t.Helper()
	config := &types.Config{
		Mode:                  ModeForwardAuth,
		OAuthClientID:         "test_client_id",
		OAuthClientSecret:     "test_client_secret",
		OAuthAuthorizeURL:     "https://accounts.google.com",
		ScopesSupported:       "openid,profile,email",
		TrustForwardedHeaders: trust,
		XFFTrustedHopCount:    hopCount,
	}
	p, err := NewOAuthProxy(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// TestTrustForwardedRateLimitClientIP verifies the rate-limit client IP
// (handlerutils.GetClientIP, read through the context injected by withCORS)
// under the configurable XFF trusted-hop-count semantics. With the default hop
// count of 0, a spoofed X-Forwarded-For is ignored and RemoteAddr is used, so a
// client cannot rotate the per-IP rate-limit key. With a positive hop count the
// real client IP is taken N positions from the RIGHT, and spoofed leftmost
// entries cannot change the key.
func TestTrustForwardedRateLimitClientIP(t *testing.T) {
	capture := func(p *OAuthProxy, xff string) string {
		var captured string
		h := p.withCORS(func(w http.ResponseWriter, r *http.Request) {
			captured = handlerutils.GetClientIP(r)
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest("GET", "/anything", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", xff)
		h.ServeHTTP(httptest.NewRecorder(), req)
		return captured
	}

	t.Run("Disabled_DropsSpoofedXFF", func(t *testing.T) {
		p := newTrustClientIPProxy(t, boolPtr(false), 1)
		got := capture(p, "203.0.113.7")
		assert.Equal(t, "10.0.0.1", got,
			"trust=false must use RemoteAddr host, not spoofed X-Forwarded-For")
	})

	t.Run("Default_NoHopCount_UsesRemoteAddr", func(t *testing.T) {
		p := newTrustClientIPProxy(t, nil, 0) // nil => trust, N=0
		got := capture(p, "203.0.113.7")
		assert.Equal(t, "10.0.0.1", got,
			"default hop count 0 must use RemoteAddr (XFF not trusted for key)")
	})

	t.Run("Enabled_HopCount1_UsesRightmost", func(t *testing.T) {
		p := newTrustClientIPProxy(t, boolPtr(true), 1)
		got := capture(p, "203.0.113.7")
		assert.Equal(t, "203.0.113.7", got,
			"trust=true, N=1 must use the rightmost XFF entry")
	})

	t.Run("Enabled_HopCount1_SpoofedExtraEntryIgnored", func(t *testing.T) {
		// A client adds a spoofed leftmost entry; with N=1 the key (rightmost
		// entry added by the trusted LB) must NOT change.
		p := newTrustClientIPProxy(t, boolPtr(true), 1)
		base := capture(p, "203.0.113.7")
		spoofed := capture(p, "1.2.3.4, 203.0.113.7")
		assert.Equal(t, base, spoofed,
			"a spoofed extra leftmost XFF entry must not change the rate-limit key with N=1")
		assert.Equal(t, "203.0.113.7", spoofed)
	})
}
