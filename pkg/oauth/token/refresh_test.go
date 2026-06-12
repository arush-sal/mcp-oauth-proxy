package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/authz"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultSession returns the default resolved session config (defaults
// reproduce the historical 1h access / 720h refresh behavior).
func defaultSession() types.SessionConfig {
	sc, err := types.ResolveSessionConfig(&types.Config{})
	if err != nil {
		panic(err)
	}
	return sc
}

// fakeStore is an in-memory token.TokenStore for refresh_token grant tests.
type fakeStore struct {
	client *types.ClientInfo
	grant  *types.Grant
	// token rows keyed by refresh token value (plaintext, as the real store
	// returns the original refresh token from GetTokenByRefreshToken).
	tokens map[string]*types.TokenData

	stored        []*types.TokenData
	revoked       []string
	revokedGrants []string
	codeConsumed  bool
}

func (s *fakeStore) GetClient(string) (*types.ClientInfo, error) { return s.client, nil }
func (s *fakeStore) StoreToken(t *types.TokenData) error {
	s.stored = append(s.stored, t)
	if s.tokens == nil {
		s.tokens = map[string]*types.TokenData{}
	}
	// Index the new token so a subsequent refresh with it succeeds.
	cp := *t
	s.tokens[t.RefreshToken] = &cp
	return nil
}
func (s *fakeStore) ValidateAuthCode(string) (string, string, error) {
	return s.grant.ID, s.grant.UserID, nil
}
func (s *fakeStore) ConsumeAuthCode(string) (string, string, error) {
	if s.codeConsumed {
		return "", "", assertNotFound{}
	}
	s.codeConsumed = true
	return s.grant.ID, s.grant.UserID, nil
}
func (s *fakeStore) GetGrant(string, string) (*types.Grant, error) { return s.grant, nil }
func (s *fakeStore) GetTokenByRefreshToken(rt string) (*types.TokenData, error) {
	td, ok := s.tokens[rt]
	if !ok || td.Revoked {
		return nil, assertNotFound{}
	}
	cp := *td
	cp.RefreshToken = rt
	return &cp, nil
}
func (s *fakeStore) RevokeToken(token string) error {
	s.revoked = append(s.revoked, token)
	if td, ok := s.tokens[token]; ok {
		td.Revoked = true
	}
	return nil
}
func (s *fakeStore) RevokeTokensByGrant(grantID string) error {
	s.revokedGrants = append(s.revokedGrants, grantID)
	for _, td := range s.tokens {
		if td.GrantID == grantID {
			td.Revoked = true
		}
	}
	return nil
}

type assertNotFound struct{}

func (assertNotFound) Error() string { return "token not found" }

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

func newRefreshRequest(refreshToken, clientID string) *http.Request {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func baseStore(t *testing.T, claims idtoken.Claims) *fakeStore {
	t.Helper()
	return &fakeStore{
		client: &types.ClientInfo{ClientID: "client", TokenEndpointAuthMethod: "none"},
		grant:  grantWithClaims(t, claims),
		tokens: map[string]*types.TokenData{
			"old-refresh": {
				AccessToken:           "old-access",
				RefreshToken:          "old-refresh",
				ClientID:              "client",
				UserID:                "user-1",
				GrantID:               "grant-1",
				ExpiresAt:             time.Now().Add(time.Hour),
				RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
			},
		},
	}
}

func newAuthCodeRequest(code, clientID string) *http.Request {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("code_verifier", "challenge")
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// authCodeStore returns a fakeStore whose grant is usable for the
// authorization_code grant (ValidateAuthCode returns its grantID/userID and the
// grant's ClientID matches "client").
func authCodeStore(t *testing.T) *fakeStore {
	t.Helper()
	s := &fakeStore{
		client: &types.ClientInfo{ClientID: "client", TokenEndpointAuthMethod: "none"},
		grant: &types.Grant{
			ID:       "grant-1",
			UserID:   "user-1",
			ClientID: "client",
			// PKCE is enabled so redirect_uri is not required (OAuth 2.1).
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "plain",
		},
	}
	return s
}

func TestAuthorizationCodeGrant_RejectsMissingPKCEVerifier(t *testing.T) {
	store := authCodeStore(t)
	h := NewHandler(store, nil, make([]byte, 32), defaultSession())
	req := newAuthCodeRequest("the-code", "client")
	require.NoError(t, req.ParseForm())
	req.Form.Del("code_verifier")
	req.PostForm.Del("code_verifier")
	req.Body = http.NoBody

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "code_verifier is required")
	assert.Empty(t, store.stored)
	assert.False(t, store.codeConsumed, "failed PKCE validation must not consume the code")
}

func TestAuthorizationCodeGrant_RejectsSecondRedemption(t *testing.T) {
	store := authCodeStore(t)
	h := NewHandler(store, nil, make([]byte, 32), defaultSession())

	first := httptest.NewRecorder()
	h.ServeHTTP(first, newAuthCodeRequest("the-code", "client"))
	require.Equal(t, http.StatusOK, first.Code)

	second := httptest.NewRecorder()
	h.ServeHTTP(second, newAuthCodeRequest("the-code", "client"))
	assert.Equal(t, http.StatusBadRequest, second.Code)
	assert.Len(t, store.stored, 1, "only the atomic consume winner may receive tokens")
}

// TestAuthorizationCodeGrant_RefreshTokenExpiresAtHonorsCustomConfig is the
// regression guard for the BLOCKER: handleAuthorizationCodeGrant must set the
// stored TokenData.RefreshTokenExpiresAt from the session RefreshTTL. Before the
// fix it left RefreshTokenExpiresAt zero, so db.StoreToken applied a hardcoded
// 30-day (720h) fallback and a custom COOKIE_REFRESH was silently ignored. A
// non-720h custom value (240h) exposes the bug: red asserts ~720h, green ~240h.
func TestAuthorizationCodeGrant_RefreshTokenExpiresAtHonorsCustomConfig(t *testing.T) {
	store := authCodeStore(t)
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	session, err := types.ResolveSessionConfig(&types.Config{CookieRefresh: "240h"})
	require.NoError(t, err)

	h := NewHandler(store, a, make([]byte, 32), session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newAuthCodeRequest("the-code", "client"))

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, store.stored)
	tok := store.stored[len(store.stored)-1]
	assert.InDelta(t, (240 * time.Hour).Seconds(), time.Until(tok.RefreshTokenExpiresAt).Seconds(), 30,
		"auth-code grant must persist RefreshTokenExpiresAt from the custom RefreshTTL, not the 720h fallback")
}

// TestAuthorizationCodeGrant_RefreshTokenExpiresAtDefault proves the default
// session reproduces the historical ~720h refresh expiry on the auth-code grant.
func TestAuthorizationCodeGrant_RefreshTokenExpiresAtDefault(t *testing.T) {
	store := authCodeStore(t)
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	h := NewHandler(store, a, make([]byte, 32), defaultSession())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newAuthCodeRequest("the-code", "client"))

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, store.stored)
	tok := store.stored[len(store.stored)-1]
	assert.InDelta(t, (720 * time.Hour).Seconds(), time.Until(tok.RefreshTokenExpiresAt).Seconds(), 30)
}

// TestReauthorizeGrant_NilGrantIsInfraError proves the defensive nil-grant guard
// (LOW-RISK C): a nil grant must not panic and must be an infra error (NOT
// ErrDenied) so the caller preserves the session (CONCERN 2).
func TestReauthorizeGrant_NilGrantIsInfraError(t *testing.T) {
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)
	h := &Handler{authorizer: a, encryptionKey: make([]byte, 32)}

	err = h.reauthorizeGrant(nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, authz.ErrDenied, "a nil grant must be an infra error, not an authorization deny")
}

// TestRefreshTokenGrant_DeniesAndRevokesSession proves that when the stored
// identity is no longer authorized, the refresh_token grant returns access_denied,
// revokes the whole session, and issues NO new tokens (BLOCKER 3).
func TestRefreshTokenGrant_DeniesAndRevokesSession(t *testing.T) {
	store := baseStore(t, idtoken.Claims{Email: "user@removed.com", EmailVerified: true})
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}}) // no longer matches
	require.NoError(t, err)

	h := NewHandler(store, a, make([]byte, 32), defaultSession())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRefreshRequest("old-refresh", "client"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	var oerr types.OAuthError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &oerr))
	assert.Equal(t, "access_denied", oerr.Error)

	assert.Contains(t, store.revokedGrants, "grant-1", "the whole session must be revoked")
	assert.Empty(t, store.stored, "no new tokens may be issued on deny")
}

// TestRefreshTokenGrant_NilAuthorizerDenies proves the path fails closed when
// no authorizer is wired (CONCERN 1).
func TestRefreshTokenGrant_NilAuthorizerDenies(t *testing.T) {
	store := baseStore(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})

	h := NewHandler(store, nil, make([]byte, 32), defaultSession())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRefreshRequest("old-refresh", "client"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, store.stored, "no tokens issued when authorizer is nil")
}

// TestRefreshTokenGrant_RotatesAndRevokesOldToken proves a successful refresh
// issues a new token, revokes the OLD refresh token (not the new one), and the
// new refresh token works while the old one no longer does (BLOCKER 4).
func TestRefreshTokenGrant_RotatesAndRevokesOldToken(t *testing.T) {
	store := baseStore(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	h := NewHandler(store, a, make([]byte, 32), defaultSession())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRefreshRequest("old-refresh", "client"))

	require.Equal(t, http.StatusOK, rec.Code)
	var resp types.TokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.RefreshToken)
	assert.NotEqual(t, "old-refresh", resp.RefreshToken, "a new refresh token must be issued")

	// The OLD refresh token was revoked (BLOCKER 4): it is the one passed to
	// RevokeToken, not the new one.
	assert.Contains(t, store.revoked, "old-refresh")
	assert.NotContains(t, store.revoked, resp.RefreshToken, "the NEW refresh token must not be revoked")

	// The old token is now unusable.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, newRefreshRequest("old-refresh", "client"))
	assert.Equal(t, http.StatusUnauthorized, rec2.Code, "old refresh token must be rejected after rotation")

	// The new token works.
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, newRefreshRequest(resp.RefreshToken, "client"))
	assert.Equal(t, http.StatusOK, rec3.Code, "new refresh token must be usable")
}

// TestRefreshTokenGrant_TTLDefaultsReproduceLegacy proves the refresh_token
// grant issues a token whose ExpiresIn and DB expiries match the historical
// 3600 / 2592000 defaults.
func TestRefreshTokenGrant_TTLDefaultsReproduceLegacy(t *testing.T) {
	store := baseStore(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	h := NewHandler(store, a, make([]byte, 32), defaultSession())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRefreshRequest("old-refresh", "client"))

	require.Equal(t, http.StatusOK, rec.Code)
	var resp types.TokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 3600, resp.ExpiresIn, "ExpiresIn = default AccessTTL seconds")

	require.NotEmpty(t, store.stored)
	newTok := store.stored[len(store.stored)-1]
	assert.InDelta(t, time.Hour.Seconds(), time.Until(newTok.ExpiresAt).Seconds(), 30)
	assert.InDelta(t, (720 * time.Hour).Seconds(), time.Until(newTok.RefreshTokenExpiresAt).Seconds(), 30)
}

// TestRefreshTokenGrant_TTLHonorsCustomConfig proves a custom session config is
// reflected in ExpiresIn and both DB expiries.
func TestRefreshTokenGrant_TTLHonorsCustomConfig(t *testing.T) {
	store := baseStore(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	a, err := authz.New(authz.Config{EmailDomains: []string{"example.com"}})
	require.NoError(t, err)

	session, err := types.ResolveSessionConfig(&types.Config{CookieExpire: "45m", CookieRefresh: "10h"})
	require.NoError(t, err)

	h := NewHandler(store, a, make([]byte, 32), session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRefreshRequest("old-refresh", "client"))

	require.Equal(t, http.StatusOK, rec.Code)
	var resp types.TokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, int((45 * time.Minute).Seconds()), resp.ExpiresIn)

	require.NotEmpty(t, store.stored)
	newTok := store.stored[len(store.stored)-1]
	assert.InDelta(t, (45 * time.Minute).Seconds(), time.Until(newTok.ExpiresAt).Seconds(), 30)
	assert.InDelta(t, (10 * time.Hour).Seconds(), time.Until(newTok.RefreshTokenExpiresAt).Seconds(), 30)
}
