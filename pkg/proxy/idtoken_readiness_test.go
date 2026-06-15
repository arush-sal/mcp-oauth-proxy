package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/callback"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidcConfig returns a config with all OIDC params present so a verifier is
// EXPECTED. The build path is driven deterministically via the idtokenBuild /
// idtokenSleep seams in the individual tests.
func oidcConfig() *types.Config {
	return &types.Config{
		Mode:                ModeForwardAuth,
		OAuthClientID:       "client-123",
		OAuthClientSecret:   "secret",
		OAuthAuthorizeURL:   "https://accounts.google.com/o/oauth2/v2/auth",
		OAuthIssuerURL:      "https://accounts.google.com",
		OAuthJWKSURL:        "https://accounts.google.com/jwks-unreachable",
		ScopesSupported:     "openid,email",
		AllowedEmailDomains: []string{"example.com"},
		ReadyPath:           "/readyz",
		HealthPath:          "/healthz",
	}
}

// TestReadinessFailsWhenIDTokenVerifierExpectedButDisabled is the core H2 test:
// when all OIDC params are configured but the verifier build always fails, the
// proxy must serve readiness 503 (fail-closed, out of rotation) with a clear
// reason, while liveness stays 200 (process is up).
func TestReadinessFailsWhenIDTokenVerifierExpectedButDisabled(t *testing.T) {
	p := newTestProxy(t, oidcConfig())
	// Force the verifier build to always fail without any network access.
	p.idtokenSleep = func(time.Duration) {}
	p.idtokenBuild = func() (callback.IDTokenVerifier, error) {
		return nil, errors.New("JWKS endpoint unreachable")
	}
	handler := p.GetHandler()

	// Readiness must fail closed: 503 with the verification-unavailable reason.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "id_token verification")

	// Liveness must stay 200: the process is up, just out of rotation.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

// TestReadinessOKWhenIDTokenVerifierBuilds confirms that when OIDC params are
// present AND the verifier builds, readiness is healthy (DB ok).
func TestReadinessOKWhenIDTokenVerifierBuilds(t *testing.T) {
	p := newTestProxy(t, oidcConfig())
	p.idtokenSleep = func(time.Duration) {}
	p.idtokenBuild = func() (callback.IDTokenVerifier, error) {
		return okVerifier{}, nil
	}
	handler := p.GetHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

// TestReadinessOKWhenNonOIDC confirms that a non-OIDC setup (no JWKS/issuer/
// clientID) yields a legitimately nil verifier and readiness stays healthy: a
// nil verifier here is expected, not a degraded security control.
func TestReadinessOKWhenNonOIDC(t *testing.T) {
	// Build a proxy WITHOUT OIDC params. newTestProxy defaults the client ID
	// when empty, so set explicit non-OIDC values: a client ID/secret/authorize
	// URL for the provider, but NO JWKS URL and NO issuer => verifier not
	// expected.
	p := newTestProxy(t, &types.Config{
		Mode:                ModeForwardAuth,
		OAuthClientID:       "client-123",
		OAuthClientSecret:   "secret",
		OAuthAuthorizeURL:   "https://accounts.google.com/o/oauth2/v2/auth",
		ScopesSupported:     "openid,email",
		AllowedEmailDomains: []string{"example.com"},
		// No OAuthJWKSURL, no OAuthIssuerURL beyond the derived one is fine
		// because without a JWKS URL the verifier is not expected.
	})
	// The build seam must never matter here, but guard against accidental use.
	p.idtokenBuild = func() (callback.IDTokenVerifier, error) {
		return nil, errors.New("should not be called for non-OIDC setup")
	}
	handler := p.GetHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

// TestReadinessDBFailureStillFailsClosed confirms the existing DB-ping behavior
// is preserved independently of the new id_token check.
func TestReadinessDBFailureStillFailsClosed(t *testing.T) {
	p := newTestProxy(t, &types.Config{ReadyPath: "/ready"})
	p.readinessPing = func(context.Context) error {
		return errors.New("db down")
	}
	handler := p.GetHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "database")
}

// TestIDTokenVerificationUnavailableState_OnlySetOnDegrade asserts the state
// flag is set only in the params-present-but-build-failed branch, and is NOT
// set for the non-OIDC case or the success case.
func TestIDTokenVerificationUnavailableState_OnlySetOnDegrade(t *testing.T) {
	t.Run("degrade sets the flag", func(t *testing.T) {
		p := newVerifierTestProxy(t, &types.Config{
			OAuthAuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			OAuthJWKSURL:      "https://accounts.google.com/jwks-unreachable",
			OAuthClientID:     "client-123",
		})
		p.idtokenSleep = func(time.Duration) {}
		p.idtokenBuild = func() (callback.IDTokenVerifier, error) {
			return nil, errors.New("down")
		}
		_ = captureLog(func() { p.buildIDTokenVerifier() })
		require.True(t, p.idTokenVerificationUnavailable(), "flag must be set on the params-present-but-build-failed branch")
	})

	t.Run("non-OIDC does not set the flag", func(t *testing.T) {
		p := newVerifierTestProxy(t, &types.Config{
			OAuthAuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			// No JWKS URL, no client ID => not expected.
		})
		p.buildIDTokenVerifier()
		require.False(t, p.idTokenVerificationUnavailable(), "flag must NOT be set for a non-OIDC setup")
	})

	t.Run("success does not set the flag", func(t *testing.T) {
		p := newVerifierTestProxy(t, &types.Config{
			OAuthAuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			OAuthJWKSURL:      "https://accounts.google.com/jwks",
			OAuthClientID:     "client-123",
			OAuthIssuerURL:    "https://accounts.google.com",
		})
		p.idtokenSleep = func(time.Duration) {}
		p.idtokenBuild = func() (callback.IDTokenVerifier, error) {
			return okVerifier{}, nil
		}
		_ = captureLog(func() { p.buildIDTokenVerifier() })
		require.False(t, p.idTokenVerificationUnavailable(), "flag must NOT be set when the verifier builds")
	})
}
