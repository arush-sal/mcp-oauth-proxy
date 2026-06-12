package validate

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/authz"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTokenStore is an in-memory TokenStore for refresh re-check tests.
type fakeTokenStore struct {
	grant         *types.Grant
	revoked       []string
	revokedGrants []string
	grantErr      error
	refreshData   *types.TokenData
	stored        []*types.TokenData
}

func (s *fakeTokenStore) GetToken(string) (*types.TokenData, error) { return nil, nil }
func (s *fakeTokenStore) GetTokenByRefreshToken(string) (*types.TokenData, error) {
	if s.refreshData != nil {
		return s.refreshData, nil
	}
	return nil, nil
}
func (s *fakeTokenStore) StoreToken(td *types.TokenData) error {
	s.stored = append(s.stored, td)
	return nil
}
func (s *fakeTokenStore) StoreAuthRequest(string, map[string]any) error { return nil }
func (s *fakeTokenStore) RevokeToken(token string) error {
	s.revoked = append(s.revoked, token)
	return nil
}
func (s *fakeTokenStore) RevokeTokensByGrant(grantID string) error {
	s.revokedGrants = append(s.revokedGrants, grantID)
	return nil
}
func (s *fakeTokenStore) GetGrant(grantID, userID string) (*types.Grant, error) {
	if s.grantErr != nil {
		return nil, s.grantErr
	}
	return s.grant, nil
}

func grantWithClaims(t *testing.T, claims idtoken.Claims) *types.Grant {
	t.Helper()
	b, err := json.Marshal(&claims)
	require.NoError(t, err)
	return &types.Grant{
		ID:     "grant-1",
		UserID: "user-1",
		// Plaintext props (no "encrypted" flag) pass through DecryptPropsIfNeeded.
		Props: map[string]any{"id_token_claims": string(b)},
	}
}

func newValidator(store TokenStore, a *authz.Authorizer) *TokenValidator {
	return &TokenValidator{
		db:            store,
		encryptionKey: make([]byte, 32),
		authorizer:    a,
	}
}

func TestReauthorizeStoredGrant_StillMatching(t *testing.T) {
	store := &fakeTokenStore{grant: grantWithClaims(t, idtoken.Claims{
		Email:         "user@example.com",
		EmailVerified: true,
	})}
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)
	v := newValidator(store, a)

	require.NoError(t, v.reauthorizeStoredGrant("grant-1", "user-1"))
}

func TestReauthorizeStoredGrant_NoLongerMatching(t *testing.T) {
	store := &fakeTokenStore{grant: grantWithClaims(t, idtoken.Claims{
		Email:         "user@removed.com",
		EmailVerified: true,
	})}
	// Allowlist no longer includes the user's domain.
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)
	v := newValidator(store, a)

	err = v.reauthorizeStoredGrant("grant-1", "user-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, authz.ErrDenied)
}

func TestReauthorizeStoredGrant_DenyAllByDefault(t *testing.T) {
	store := &fakeTokenStore{grant: grantWithClaims(t, idtoken.Claims{
		Email:         "user@example.com",
		EmailVerified: true,
	})}
	a, err := authz.New(authz.Config{}) // zero-config => deny all
	require.NoError(t, err)
	v := newValidator(store, a)

	assert.ErrorIs(t, v.reauthorizeStoredGrant("grant-1", "user-1"), authz.ErrDenied)
}

func TestRevokeGrantTokens(t *testing.T) {
	store := &fakeTokenStore{}
	v := newValidator(store, nil)

	v.revokeGrantTokens("refresh-tok", &types.TokenData{AccessToken: "access-tok", GrantID: "grant-1"})

	assert.Contains(t, store.revoked, "refresh-tok")
	assert.Contains(t, store.revoked, "access-tok")
	// BLOCKER 2: the whole session (grant) must be revoked, not just the pair.
	assert.Contains(t, store.revokedGrants, "grant-1")
}

func TestReauthorizeStoredGrant_NilAuthorizerDenies(t *testing.T) {
	// CONCERN 1: a nil authorizer must fail closed (deny), not allow.
	store := &fakeTokenStore{grant: grantWithClaims(t, idtoken.Claims{
		Email: "user@example.com", EmailVerified: true,
	})}
	v := newValidator(store, nil)

	err := v.reauthorizeStoredGrant("grant-1", "user-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, authz.ErrDenied)
}

func TestReauthorizeStoredGrant_InfraErrorIsNotDenied(t *testing.T) {
	// CONCERN 2: a grant-load failure is an infra error, not an authorization
	// deny, so it must NOT be classified as ErrDenied (caller must not revoke
	// the session on a transient blip).
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)
	store := &fakeTokenStore{grantErr: errors.New("db connection refused")}
	v := newValidator(store, a)

	err = v.reauthorizeStoredGrant("grant-1", "user-1")
	require.Error(t, err)
	assert.NotErrorIs(t, err, authz.ErrDenied, "infra error must not be an authorization deny")
}

func TestReauthorizeStoredGrant_NilGrantIsInfraError(t *testing.T) {
	// LOW-RISK C: GetGrant returning (nil, nil) must not panic; it is treated as
	// an infra error (NOT ErrDenied) so the session is not revoked (CONCERN 2).
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)
	// grant is nil and grantErr is nil => GetGrant returns (nil, nil).
	store := &fakeTokenStore{}
	v := newValidator(store, a)

	err = v.reauthorizeStoredGrant("grant-1", "user-1")
	require.Error(t, err)
	assert.NotErrorIs(t, err, authz.ErrDenied, "a nil grant must be an infra error, not an authorization deny")
}

// fakeTokenDatabase is the tokens.Database needed by the TokenManager to resolve
// a "userID:grantID:secret" cookie token in the WithTokenValidation middleware.
type fakeTokenDatabase struct {
	tokenData *types.TokenData
	grant     *types.Grant
}

func (d *fakeTokenDatabase) GetToken(string) (*types.TokenData, error) {
	return d.tokenData, nil
}
func (d *fakeTokenDatabase) GetGrant(string, string) (*types.Grant, error) {
	return d.grant, nil
}

// newCookieValidator builds a validator wired to drive the cookie refresh path
// in WithTokenValidation: the tokenManager resolves the access-token cookie and
// p.db drives refreshAccessToken.
func newCookieValidator(t *testing.T, store TokenStore, a *authz.Authorizer, tokenData *types.TokenData, grant *types.Grant) *TokenValidator {
	t.Helper()
	return newCookieValidatorWithSession(t, store, a, tokenData, grant, defaultSession(t))
}

func newCookieValidatorWithSession(t *testing.T, store TokenStore, a *authz.Authorizer, tokenData *types.TokenData, grant *types.Grant, session types.SessionConfig) *TokenValidator {
	t.Helper()
	tm, err := tokens.NewTokenManager(&fakeTokenDatabase{tokenData: tokenData, grant: grant})
	require.NoError(t, err)
	return &TokenValidator{
		tokenManager:           tm,
		db:                     store,
		encryptionKey:          make([]byte, 32),
		authorizer:             a,
		accessTokenCookieName:  "access_token",
		refreshTokenCookieName: "refresh_token",
		session:                session,
	}
}

// defaultSession returns the default resolved session config.
func defaultSession(t *testing.T) types.SessionConfig {
	t.Helper()
	sc, err := types.ResolveSessionConfig(&types.Config{})
	require.NoError(t, err)
	return sc
}

func cookieRequest(t *testing.T, key []byte, accessToken, refreshToken string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/mcp", nil)
	// Non-browser UA so sendUnauthorizedResponse returns a 401 instead of
	// redirecting to the OAuth flow.
	req.Header.Set("User-Agent", "test-agent")
	encAccess, err := encryption.EncryptCookie(key, accessToken)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: encAccess})
	encRefresh, err := encryption.EncryptCookie(key, refreshToken)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: encRefresh})
	return req
}

func TestWithTokenValidation_ErrDeniedRefreshBlocksValidToken(t *testing.T) {
	// BLOCKER B: when refresh fails because authorization was REVOKED
	// (errors.Is(refreshErr, authz.ErrDenied)), the in-flight request must be
	// blocked (401) even though the current cookie token is still valid for ~5
	// more minutes.
	key := make([]byte, 32)
	const userID, grantID = "user-1", "grant-1"
	accessToken := userID + ":" + grantID + ":access-secret"
	refreshToken := userID + ":" + grantID + ":refresh-secret"

	// Current cookie token: valid but within the 15-minute refresh window.
	tokenData := &types.TokenData{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		UserID:                userID,
		GrantID:               grantID,
		ExpiresAt:             time.Now().Add(5 * time.Minute),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
	}
	// The grant the refresh re-check will re-authorize: a domain the allowlist
	// no longer permits => ErrDenied.
	grant := grantWithClaims(t, idtoken.Claims{Email: "user@removed.com", EmailVerified: true})
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	store := &fakeTokenStore{grant: grant, refreshData: tokenData}
	v := newCookieValidator(t, store, a, tokenData, grant)

	called := false
	handler := v.WithTokenValidation(func(http.ResponseWriter, *http.Request) { called = true })

	rec := httptest.NewRecorder()
	handler(rec, cookieRequest(t, key, accessToken, refreshToken))

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "revoked authorization must block the in-flight request")
	assert.False(t, called, "downstream handler must NOT run when authorization was revoked")
	assert.Contains(t, store.revokedGrants, grantID, "the session must be revoked on an ErrDenied refresh")
}

func TestWithTokenValidation_InfraRefreshErrorContinuesWithValidToken(t *testing.T) {
	// BLOCKER B / CONCERN 2: a non-ErrDenied (infrastructure) refresh error with a
	// still-valid token must NOT block the request — a transient blip continues
	// with the current token.
	key := make([]byte, 32)
	const userID, grantID = "user-1", "grant-1"
	accessToken := userID + ":" + grantID + ":access-secret"
	refreshToken := userID + ":" + grantID + ":refresh-secret"

	tokenData := &types.TokenData{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		UserID:                userID,
		GrantID:               grantID,
		ExpiresAt:             time.Now().Add(5 * time.Minute),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
	}
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	// The tokenManager must still resolve the cookie token, so the database
	// returns a valid grant. The validator's own p.db (store) is what drives the
	// refresh re-check, and there grantErr makes reauthorizeStoredGrant return a
	// NON-ErrDenied infra error.
	dbGrant := grantWithClaims(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	store := &fakeTokenStore{grantErr: errors.New("db connection refused"), refreshData: tokenData}
	v := newCookieValidator(t, store, a, tokenData, dbGrant)

	called := false
	handler := v.WithTokenValidation(func(http.ResponseWriter, *http.Request) { called = true })

	rec := httptest.NewRecorder()
	handler(rec, cookieRequest(t, key, accessToken, refreshToken))

	assert.True(t, called, "infra refresh error with a still-valid token must continue to the handler")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, store.revokedGrants, "an infra error must NOT revoke the session")
}

// TestRefreshCookieAttributesHonored drives the cookie refresh path and asserts
// the rotated access/refresh cookies carry the configured MaxAge, Secure, and
// SameSite, and that the new token DB row uses the configured TTLs.
func TestRefreshCookieAttributesHonored(t *testing.T) {
	key := make([]byte, 32)
	const userID, grantID = "user-1", "grant-1"
	accessToken := userID + ":" + grantID + ":access-secret"
	refreshToken := userID + ":" + grantID + ":refresh-secret"

	// Cookie token valid but within the 15-minute refresh window so refresh runs.
	tokenData := &types.TokenData{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		UserID:                userID,
		GrantID:               grantID,
		ExpiresAt:             time.Now().Add(5 * time.Minute),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
	}
	grant := grantWithClaims(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	session, err := types.ResolveSessionConfig(&types.Config{
		CookieExpire:   "30m",
		CookieRefresh:  "2h",
		CookieSecure:   "true",
		CookieSameSite: "strict",
	})
	require.NoError(t, err)

	store := &fakeTokenStore{grant: grant, refreshData: tokenData}
	v := newCookieValidatorWithSession(t, store, a, tokenData, grant, session)

	called := false
	handler := v.WithTokenValidation(func(http.ResponseWriter, *http.Request) { called = true })

	rec := httptest.NewRecorder()
	// Plain HTTP request; Secure must still be true because COOKIE_SECURE=true.
	req := cookieRequest(t, key, accessToken, refreshToken)
	req.URL.Scheme = "http"
	req.TLS = nil
	req.Header.Del("X-Forwarded-Proto")
	handler(rec, req)

	require.True(t, called, "refresh should succeed and call the downstream handler")
	cookies := rec.Result().Cookies()

	access := findRespCookie(cookies, "access_token")
	require.NotNil(t, access, "rotated access cookie must be set")
	assert.Equal(t, 1800, access.MaxAge)
	assert.True(t, access.Secure, "COOKIE_SECURE=true forces Secure even on plain HTTP")
	assert.Equal(t, http.SameSiteStrictMode, access.SameSite)

	refresh := findRespCookie(cookies, "refresh_token")
	require.NotNil(t, refresh, "rotated refresh cookie must be set")
	assert.Equal(t, 7200, refresh.MaxAge)
	assert.True(t, refresh.Secure)
	assert.Equal(t, http.SameSiteStrictMode, refresh.SameSite)

	// The new token DB row reflects the configured TTLs.
	require.NotEmpty(t, store.stored)
	newTok := store.stored[len(store.stored)-1]
	assert.InDelta(t, (30 * time.Minute).Seconds(), time.Until(newTok.ExpiresAt).Seconds(), 30)
	assert.InDelta(t, (2 * time.Hour).Seconds(), time.Until(newTok.RefreshTokenExpiresAt).Seconds(), 30)
}

func TestRefreshAccessTokenRevokesOldTokenPair(t *testing.T) {
	key := make([]byte, 32)
	const userID, grantID = "user-1", "grant-1"
	accessToken := userID + ":" + grantID + ":access-secret"
	refreshToken := userID + ":" + grantID + ":refresh-secret"
	tokenData := &types.TokenData{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		UserID:                userID,
		GrantID:               grantID,
		ExpiresAt:             time.Now().Add(5 * time.Minute),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
	}
	grant := grantWithClaims(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	store := &fakeTokenStore{grant: grant, refreshData: tokenData}
	v := newCookieValidator(t, store, a, tokenData, grant)
	rec := httptest.NewRecorder()

	_, err = v.refreshAccessToken(rec, cookieRequest(t, key, accessToken, refreshToken))

	require.NoError(t, err)
	assert.Contains(t, store.revoked, refreshToken,
		"cookie rotation must revoke the row backing the old refresh/access token pair")
}

// TestRefreshCookieDefaultsReproduceLegacy confirms default config yields the
// historical 3600 / 2592000 MaxAge, Lax SameSite, and auto Secure (off on HTTP).
func TestRefreshCookieDefaultsReproduceLegacy(t *testing.T) {
	key := make([]byte, 32)
	const userID, grantID = "user-1", "grant-1"
	accessToken := userID + ":" + grantID + ":access-secret"
	refreshToken := userID + ":" + grantID + ":refresh-secret"

	tokenData := &types.TokenData{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		UserID:                userID,
		GrantID:               grantID,
		ExpiresAt:             time.Now().Add(5 * time.Minute),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
	}
	grant := grantWithClaims(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	store := &fakeTokenStore{grant: grant, refreshData: tokenData}
	v := newCookieValidator(t, store, a, tokenData, grant) // default session

	handler := v.WithTokenValidation(func(http.ResponseWriter, *http.Request) {})
	rec := httptest.NewRecorder()
	req := cookieRequest(t, key, accessToken, refreshToken)
	req.URL.Scheme = "http"
	req.TLS = nil
	req.Header.Del("X-Forwarded-Proto")
	handler(rec, req)

	cookies := rec.Result().Cookies()
	access := findRespCookie(cookies, "access_token")
	require.NotNil(t, access)
	assert.Equal(t, 3600, access.MaxAge)
	assert.False(t, access.Secure, "auto Secure off on plain HTTP (legacy)")
	assert.Equal(t, http.SameSiteLaxMode, access.SameSite)

	refresh := findRespCookie(cookies, "refresh_token")
	require.NotNil(t, refresh)
	assert.Equal(t, 30*24*3600, refresh.MaxAge)
	assert.False(t, refresh.Secure)
	assert.Equal(t, http.SameSiteLaxMode, refresh.SameSite)
}

func findRespCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
