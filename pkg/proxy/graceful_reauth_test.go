package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/authz"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/validate"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// stubProvider is a providers.Provider test double letting each test pick the
// RefreshToken outcome that drives a particular mcpProxyHandler re-auth path.
type stubProvider struct {
	refresh    *oauth2.Token
	refreshErr error
}

func newRefreshedToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "fresh-idp-token", Expiry: time.Now().Add(time.Hour)}
}

// newRefreshedTokenWithIDToken returns a refreshed token carrying a fresh
// id_token, so reauthorizeOnRefresh routes through the configured
// IDTokenVerifier. Used to exercise the infra/transient verify-failure path.
func newRefreshedTokenWithIDToken() *oauth2.Token {
	return newRefreshedToken().WithExtra(map[string]any{"id_token": "fresh.id.token"})
}

// failingVerifier is a callback.IDTokenVerifier double whose Verify always
// returns a NON-ErrDenied error, so reauthorizeOnRefresh fails closed on an
// infrastructure error (id_token verify blip) rather than an authorization
// deny. This is the seam for the transient re-auth failure path.
type failingVerifier struct{}

func (failingVerifier) Verify(context.Context, string) (*idtoken.Claims, error) {
	return nil, errors.New("transient jwks fetch failure")
}

func (s *stubProvider) GetAuthorizationURL(string, string, string, string) string { return "" }
func (s *stubProvider) GetAuthorizationURLWithPKCE(string, string, string, string, string) string {
	return ""
}
func (s *stubProvider) ExchangeCodeForToken(context.Context, string, string, string, string) (*oauth2.Token, error) {
	return nil, nil
}
func (s *stubProvider) GetUserInfo(context.Context, string) (*providers.UserInfo, error) {
	return nil, nil
}
func (s *stubProvider) RefreshToken(context.Context, string, string, string) (*oauth2.Token, error) {
	if s.refreshErr != nil {
		return nil, s.refreshErr
	}
	return s.refresh, nil
}
func (s *stubProvider) GetName() string { return "generic" }

// expiredTokenInfoCtx stages a tokenInfo whose IdP access_token is expired so
// mcpProxyHandler takes the in-request refresh branch.
func expiredTokenInfoReq(t *testing.T, grantID, userID string, claims idtoken.Claims) *http.Request {
	t.Helper()
	b, err := json.Marshal(&claims)
	require.NoError(t, err)
	ti := &tokens.TokenInfo{
		UserID:  userID,
		GrantID: grantID,
		Props: map[string]any{
			"access_token":    "stale-idp-token",
			"refresh_token":   "idp-refresh-token",
			"expires_at":      float64(time.Now().Add(-time.Hour).Unix()),
			"id_token_claims": string(b),
		},
	}
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example.com/mcp", nil)
	req.Header.Set("User-Agent", "mcp-agent/1.0")
	return req.WithContext(validate.ContextWithTokenInfo(req.Context(), ti))
}

// TestMCPProxy_RefreshFailureEmitsChallenge: provider refresh returns an error.
// The agent must get a 401 WITH the WWW-Authenticate challenge (not a bare 401,
// not a 500).
func TestMCPProxy_RefreshFailureEmitsChallenge(t *testing.T) {
	p := newTestProxy(t, &types.Config{Mode: ModeMiddleware, DatabaseDSN: filepath.Join(t.TempDir(), "t.db")})
	p.providers.RegisterProvider("generic", &stubProvider{refreshErr: errors.New("idp refused refresh")})
	p.provider = "generic"

	req := expiredTokenInfoReq(t, "grant-1", "user-1", idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	rec := httptest.NewRecorder()

	called := false
	p.mcpProxyHandler(rec, req, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	require.Equal(t, http.StatusUnauthorized, rec.Code, "refresh failure must be 401, never 500")
	assert.False(t, called, "downstream handler must not run on refresh failure")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `Bearer error="invalid_token"`,
		"refresh failure must carry a re-auth challenge, not a bare 401")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"),
		`resource_metadata="https://proxy.example.com/.well-known/oauth-protected-resource/mcp"`)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_token", body["error"])
}

// TestMCPProxy_NoRefreshTokenEmitsChallenge: token expired and there is no
// refresh token to use. 401 + challenge, not bare 401.
func TestMCPProxy_NoRefreshTokenEmitsChallenge(t *testing.T) {
	p := newTestProxy(t, &types.Config{Mode: ModeMiddleware, DatabaseDSN: filepath.Join(t.TempDir(), "t.db")})

	ti := &tokens.TokenInfo{
		UserID:  "user-1",
		GrantID: "grant-1",
		Props: map[string]any{
			"access_token": "stale-idp-token",
			"expires_at":   float64(time.Now().Add(-time.Hour).Unix()),
		},
	}
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example.com/mcp", nil)
	req = req.WithContext(validate.ContextWithTokenInfo(req.Context(), ti))
	rec := httptest.NewRecorder()

	called := false
	p.mcpProxyHandler(rec, req, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, called)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `Bearer error="invalid_token"`)
}

// TestMCPProxy_ReauthorizeDenyChallengesAndRevokes: F1 contract. The refresh
// succeeds at the IdP but the user is no longer on the allowlist, so the session
// is revoked AND the agent gets a 401 challenge (not a bare 401).
func TestMCPProxy_ReauthorizeDenyChallengesAndRevokes(t *testing.T) {
	p := newTestProxy(t, &types.Config{Mode: ModeMiddleware, DatabaseDSN: filepath.Join(t.TempDir(), "t.db")})

	// Allowlist only permits example.com; the staged identity is removed.com.
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)
	p.authorizer = a

	// Refresh "succeeds" at the IdP (returns a token, no fresh id_token), so the
	// deny comes from the allowlist re-check, classified as authz.ErrDenied.
	p.providers.RegisterProvider("generic", &stubProvider{refresh: newRefreshedToken()})
	p.provider = "generic"

	const grantID = "grant-deny-1"
	// Persist a token for this grant so we can confirm the session is revoked.
	accessTok := "user-1:" + grantID + ":secret"
	require.NoError(t, p.db.StoreToken(&types.TokenData{
		AccessToken:           accessTok,
		RefreshToken:          "user-1:" + grantID + ":refresh",
		ClientID:              "client-1",
		UserID:                "user-1",
		GrantID:               grantID,
		ExpiresAt:             time.Now().Add(time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
	}))

	req := expiredTokenInfoReq(t, grantID, "user-1", idtoken.Claims{Email: "user@removed.com", EmailVerified: true})
	rec := httptest.NewRecorder()

	called := false
	p.mcpProxyHandler(rec, req, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	require.Equal(t, http.StatusUnauthorized, rec.Code, "deny must be 401, never 500")
	assert.False(t, called, "downstream handler must not run on deny")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `Bearer error="invalid_token"`,
		"deny must carry a re-auth challenge, not a bare 401")

	// The challenge message must accurately state the session was revoked.
	var denyBody map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &denyBody))
	assert.Equal(t, "Access revoked: you are no longer authorized to use this resource",
		denyBody["error_description"], "a genuine deny must say the access was revoked")

	// Session revoke must have happened (precedes the response).
	td, err := p.db.GetToken(accessTok)
	require.NoError(t, err)
	assert.True(t, td.Revoked, "the whole session must be revoked on an authorization deny")
}

// TestMCPProxy_ReauthorizeInfraErrorChallengesWithoutRevoke: the IdP refresh
// succeeds and returns a fresh id_token, but verifying it fails transiently
// (a NON-ErrDenied infrastructure error). The request must fail closed with a
// 401 challenge, but the message must NOT claim the access was revoked, and the
// session must be preserved (not revoked) so a transient blip does not log
// everyone out.
func TestMCPProxy_ReauthorizeInfraErrorChallengesWithoutRevoke(t *testing.T) {
	p := newTestProxy(t, &types.Config{Mode: ModeMiddleware, DatabaseDSN: filepath.Join(t.TempDir(), "t.db")})

	// Allowlist would permit the identity; the failure comes from id_token verify.
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)
	p.authorizer = a

	// A verifier that always fails with a non-deny error is the infra seam.
	p.idTokenVerifier = failingVerifier{}

	// Refresh succeeds and returns a fresh id_token so the verifier is invoked.
	p.providers.RegisterProvider("generic", &stubProvider{refresh: newRefreshedTokenWithIDToken()})
	p.provider = "generic"

	const grantID = "grant-infra-1"
	accessTok := "user-1:" + grantID + ":secret"
	require.NoError(t, p.db.StoreToken(&types.TokenData{
		AccessToken:           accessTok,
		RefreshToken:          "user-1:" + grantID + ":refresh",
		ClientID:              "client-1",
		UserID:                "user-1",
		GrantID:               grantID,
		ExpiresAt:             time.Now().Add(time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
	}))

	req := expiredTokenInfoReq(t, grantID, "user-1", idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	rec := httptest.NewRecorder()

	called := false
	p.mcpProxyHandler(rec, req, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	require.Equal(t, http.StatusUnauthorized, rec.Code, "infra failure must be 401, never 500")
	assert.False(t, called, "downstream handler must not run on a re-auth infra failure")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `Bearer error="invalid_token"`,
		"infra failure must carry a re-auth challenge, not a bare 401")

	// The message must NOT claim revocation: the session was not revoked.
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotContains(t, body["error_description"], "Access revoked",
		"a transient infra failure must not be reported as a revocation")
	assert.Equal(t, "Re-authorization failed; please re-authenticate", body["error_description"])

	// Session must be preserved on a transient infra failure.
	td, err := p.db.GetToken(accessTok)
	require.NoError(t, err)
	assert.False(t, td.Revoked, "a transient infra failure must NOT revoke the session")
}

// TestMCPProxy_HappyRefreshPassesThrough: a valid in-request refresh renews the
// token silently and the downstream handler runs (no re-login, no challenge).
func TestMCPProxy_HappyRefreshPassesThrough(t *testing.T) {
	p := newTestProxy(t, &types.Config{
		Mode:          ModeMiddleware,
		DatabaseDSN:   filepath.Join(t.TempDir(), "t.db"),
		EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})

	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)
	p.authorizer = a

	p.providers.RegisterProvider("generic", &stubProvider{refresh: newRefreshedToken()})
	p.provider = "generic"

	const grantID = "grant-ok-1"
	require.NoError(t, p.db.StoreGrant(&types.Grant{
		ID:       grantID,
		ClientID: "client-1",
		UserID:   "user-1",
		Scope:    []string{"openid"},
		Props:    map[string]any{"email": "user@example.com"},
	}))

	req := expiredTokenInfoReq(t, grantID, "user-1", idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	rec := httptest.NewRecorder()

	called := false
	p.mcpProxyHandler(rec, req, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	assert.True(t, called, "a valid refresh must renew silently and pass through to the handler")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code)
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
}
