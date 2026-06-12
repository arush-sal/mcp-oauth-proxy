package callback

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/authz"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// fakeStore is an in-memory Store implementation for callback tests.
type fakeStore struct {
	authRequest map[string]any
	storedGrant *types.Grant
	storedToken *types.TokenData
}

func (s *fakeStore) StoreGrant(grant *types.Grant) error {
	s.storedGrant = grant
	return nil
}
func (s *fakeStore) StoreAuthCode(string, string, string) error { return nil }
func (s *fakeStore) GetAuthRequest(string) (map[string]any, error) {
	return s.authRequest, nil
}
func (s *fakeStore) DeleteAuthRequest(string) error { return nil }
func (s *fakeStore) StoreToken(td *types.TokenData) error {
	s.storedToken = td
	return nil
}

// fakeProvider returns a fixed token from ExchangeCodeForToken.
type fakeProvider struct {
	token    *oauth2.Token
	userInfo *providers.UserInfo
}

func (p *fakeProvider) GetAuthorizationURL(string, string, string, string) string { return "" }
func (p *fakeProvider) GetAuthorizationURLWithPKCE(string, string, string, string, string) string {
	return ""
}
func (p *fakeProvider) ExchangeCodeForToken(context.Context, string, string, string, string) (*oauth2.Token, error) {
	return p.token, nil
}
func (p *fakeProvider) GetUserInfo(context.Context, string) (*providers.UserInfo, error) {
	if p.userInfo != nil {
		return p.userInfo, nil
	}
	return &providers.UserInfo{ID: "user-123"}, nil
}
func (p *fakeProvider) RefreshToken(context.Context, string, string, string) (*oauth2.Token, error) {
	return nil, nil
}
func (p *fakeProvider) GetName() string { return "fake" }

// stubVerifier is a test double for IDTokenVerifier.
type stubVerifier struct {
	claims *idtoken.Claims
	err    error
}

func (v *stubVerifier) Verify(context.Context, string) (*idtoken.Claims, error) {
	return v.claims, v.err
}

var testEncryptionKey = make([]byte, 32) // all-zero AES-256 key for tests

// allowAny returns an Authorizer that allows any authenticated user (the "*"
// email-domain escape hatch), so existing tests focused on id_token storage are
// not blocked by the deny-all default.
func allowAny(t *testing.T) *authz.Authorizer {
	t.Helper()
	a, err := authz.New(authz.Config{EmailDomains: []string{"*"}})
	require.NoError(t, err)
	return a
}

// defaultSession returns the default resolved session config (defaults
// reproduce the historical 1h access / 720h refresh, auto Secure, Lax SameSite).
func defaultSession() types.SessionConfig {
	sc, err := types.ResolveSessionConfig(&types.Config{})
	if err != nil {
		panic(err)
	}
	return sc
}

func newCallbackRequest(t *testing.T) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/callback?code=abc&state=xyz", nil)
	return httptest.NewRecorder(), req
}

func decryptGrantProps(t *testing.T, grant *types.Grant) map[string]any {
	t.Helper()
	require.NotNil(t, grant)
	props, err := encryption.DecryptPropsIfNeeded(testEncryptionKey, grant.Props)
	require.NoError(t, err)
	return props
}

func TestCallback_StoresVerifiedIDTokenClaims(t *testing.T) {
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{token: token}
	verifier := &stubVerifier{claims: &idtoken.Claims{
		Email:   "user@example.com",
		Subject: "user-123",
		Groups:  []string{"admins"},
	}}

	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, allowAny(t), defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	props := decryptGrantProps(t, store.storedGrant)

	raw, ok := props["id_token_claims"].(string)
	require.True(t, ok, "id_token_claims should be stored as a string")
	var claims idtoken.Claims
	require.NoError(t, json.Unmarshal([]byte(raw), &claims))
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, []string{"admins"}, claims.Groups)
	assert.Equal(t, "raw-id-token", props["id_token"])
}

func TestCallback_NoIDTokenLeavesPropsUnchanged(t *testing.T) {
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid"}}
	// Token carries no id_token extra.
	token := &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}
	provider := &fakeProvider{token: token}
	verifier := &stubVerifier{claims: &idtoken.Claims{Email: "should-not-be-used@example.com"}}

	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, allowAny(t), defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	props := decryptGrantProps(t, store.storedGrant)
	_, hasClaims := props["id_token_claims"]
	assert.False(t, hasClaims, "no id_token_claims should be stored when no id_token is present")
	_, hasRaw := props["id_token"]
	assert.False(t, hasRaw, "no raw id_token should be stored when none is present")
}

func TestCallback_NoVerifierConfigured(t *testing.T) {
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{token: token}

	// nil verifier => non-OIDC setup, id_token ignored.
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	props := decryptGrantProps(t, store.storedGrant)
	_, hasClaims := props["id_token_claims"]
	assert.False(t, hasClaims, "no verifier means no id_token_claims even if id_token present")
}

func TestCallback_InvalidIDTokenRejected(t *testing.T) {
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{token: token}
	verifier := &stubVerifier{err: errors.New("bad signature")}

	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, allowAny(t), defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Nil(t, store.storedGrant, "no grant should be stored when id_token verification fails")
}

func newAuthorizer(t *testing.T, cfg authz.Config) *authz.Authorizer {
	t.Helper()
	a, err := authz.New(cfg)
	require.NoError(t, err)
	return a
}

func TestCallback_AllowedIdentityCreatesGrant(t *testing.T) {
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid email"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{token: token}
	verifier := &stubVerifier{claims: &idtoken.Claims{
		Email:         "user@example.com",
		EmailVerified: true,
		Subject:       "user-123",
	}}

	a := newAuthorizer(t, authz.Config{EmailDomains: []string{"example.com"}})
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a, defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	require.NotNil(t, store.storedGrant, "an allowed identity must produce a grant")
}

func TestCallback_DeniedIdentityForbiddenNoGrant(t *testing.T) {
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid email"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{token: token}
	verifier := &stubVerifier{claims: &idtoken.Claims{
		Email:         "user@notallowed.com",
		EmailVerified: true,
		Subject:       "user-123",
	}}

	a := newAuthorizer(t, authz.Config{EmailDomains: []string{"example.com"}})
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a, defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, store.storedGrant, "a denied identity must not produce a grant")

	var oerr types.OAuthError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &oerr))
	assert.Equal(t, "access_denied", oerr.Error)
}

func TestCallback_DenyAllByDefault(t *testing.T) {
	// A zero-config authorizer denies even a verified user (breaking-change default).
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid email"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{token: token}
	verifier := &stubVerifier{claims: &idtoken.Claims{
		Email:         "user@example.com",
		EmailVerified: true,
		Subject:       "user-123",
	}}

	a := newAuthorizer(t, authz.Config{})
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a, defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, store.storedGrant)
}

func TestCallback_UserInfoFallbackForEmail(t *testing.T) {
	// id_token lacks email but a domain rule needs it; the userinfo endpoint
	// supplies a verified email that satisfies the rule.
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid email"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{
		token: token,
		userInfo: &providers.UserInfo{
			ID:            "user-123",
			Email:         "user@example.com",
			EmailVerified: true,
		},
	}
	// id_token has no email at all.
	verifier := &stubVerifier{claims: &idtoken.Claims{Subject: "user-123"}}

	a := newAuthorizer(t, authz.Config{EmailDomains: []string{"example.com"}})
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a, defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	require.NotNil(t, store.storedGrant)
}

func TestCallback_StoresEmailVerifiedFromUserInfo(t *testing.T) {
	// BLOCKER 1: the actual email_verified state from userinfo must be persisted
	// (here false) so a refresh re-check does not promote it to verified.
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid email"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{
		token: token,
		userInfo: &providers.UserInfo{
			ID:            "user-123",
			Email:         "user@example.com",
			EmailVerified: false,
		},
	}
	// id_token has no email, so userinfo supplies it.
	verifier := &stubVerifier{claims: &idtoken.Claims{Subject: "user-123"}}

	// Allow-any so the grant is created regardless of verified state.
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, allowAny(t), defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	props := decryptGrantProps(t, store.storedGrant)
	assert.Equal(t, "user@example.com", props["email"])
	verified, ok := props["email_verified"].(bool)
	require.True(t, ok, "email_verified must be persisted")
	assert.False(t, verified, "stored email_verified must reflect the real (false) state")
}

func TestCallback_StoresVerifiedEmailFromUserInfo(t *testing.T) {
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid email"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{
		token: token,
		userInfo: &providers.UserInfo{
			ID:            "user-123",
			Email:         "user@example.com",
			EmailVerified: true,
		},
	}
	verifier := &stubVerifier{claims: &idtoken.Claims{Subject: "user-123"}}

	a := newAuthorizer(t, authz.Config{EmailDomains: []string{"example.com"}})
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a, defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	props := decryptGrantProps(t, store.storedGrant)
	verified, ok := props["email_verified"].(bool)
	require.True(t, ok, "email_verified must be persisted")
	assert.True(t, verified, "verified userinfo email must persist as verified")
}

func TestCallback_StoredEmailAndVerifiedAreSelfConsistent(t *testing.T) {
	// BLOCKER A: when the id_token carries a verified email A and the userinfo
	// endpoint returns a DIFFERENT, unverified email B, the stored top-level
	// email/email_verified pair must describe the SAME email (B's address with
	// B's verified state), not B's address borrowing A's verified flag. The
	// id_token's own email continues to live in id_token_claims.
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid email"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{
		token: token,
		userInfo: &providers.UserInfo{
			ID:            "user-123",
			Email:         "user@b.example.com", // different email B
			EmailVerified: false,                // and it is NOT verified
		},
	}
	// id_token email A is verified and belongs to a.example.com.
	verifier := &stubVerifier{claims: &idtoken.Claims{
		Email:         "user@a.example.com",
		EmailVerified: true,
		Subject:       "user-123",
	}}

	// Live decision is allowed via the id_token's verified A-domain email. We
	// also fetch userinfo because NeedsEmail() is true and the id_token does
	// supply an email, but the proxy still stores userinfo when scope asks for it.
	a := newAuthorizer(t, authz.Config{EmailDomains: []string{"a.example.com"}})
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a, defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	props := decryptGrantProps(t, store.storedGrant)

	// Top-level email/email_verified must be B's address with B's (false) state.
	assert.Equal(t, "user@b.example.com", props["email"], "stored top-level email is the userinfo email B")
	verified, ok := props["email_verified"].(bool)
	require.True(t, ok, "email_verified must be persisted")
	assert.False(t, verified, "stored email_verified must reflect B's real (false) state, not A's verified flag")

	// A stored-props re-check against a rule that only allows B's domain must
	// DENY: B is unverified, and the id_token_claims email belongs to a different
	// domain. So the unverified address can never be promoted to authorize B.
	bOnly := newAuthorizer(t, authz.Config{EmailDomains: []string{"b.example.com"}})
	assert.ErrorIs(t, authz.AuthorizeStoredProps(bOnly, props), authz.ErrDenied,
		"unverified userinfo email B must not authorize on a stored-props re-check")
}

func TestCallback_MissingAttributeFailsClosed(t *testing.T) {
	// A group rule is configured but neither id_token nor userinfo supplies
	// groups, so the request must be denied (fail closed).
	store := &fakeStore{authRequest: map[string]any{"client_id": "client", "scope": "openid email"}}
	token := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "raw-id-token"})
	provider := &fakeProvider{token: token, userInfo: &providers.UserInfo{ID: "user-123"}}
	verifier := &stubVerifier{claims: &idtoken.Claims{Subject: "user-123"}}

	a := newAuthorizer(t, authz.Config{Groups: []string{"admins"}})
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a, defaultSession())

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, store.storedGrant)
}

// uiCallbackRequest builds a callback request whose stored auth-request carries
// an "rd" (relative redirect), triggering the UI cookie-setting flow.
func uiCallbackRequest(t *testing.T, secureScheme bool) (*httptest.ResponseRecorder, *http.Request, *fakeStore) {
	t.Helper()
	store := &fakeStore{authRequest: map[string]any{
		"client_id": "client",
		"scope":     "openid",
		"rd":        "/dashboard",
	}}
	rec := httptest.NewRecorder()
	scheme := "https"
	if !secureScheme {
		scheme = "http"
	}
	req := httptest.NewRequest(http.MethodGet, scheme+"://proxy.example.com/callback?code=abc&state=xyz", nil)
	if !secureScheme {
		// httptest.NewRequest sets TLS for https URLs; clear it for the plain case.
		req.TLS = nil
	}
	return rec, req, store
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestCallback_CookieAttributesHonored(t *testing.T) {
	provider := &fakeProvider{token: &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}}

	// Custom session: 30m access, 2h refresh, force Secure, SameSite=Strict.
	session, err := types.ResolveSessionConfig(&types.Config{
		CookieExpire:   "30m",
		CookieRefresh:  "2h",
		CookieSecure:   "true",
		CookieSameSite: "strict",
	})
	require.NoError(t, err)

	rec, req, store := uiCallbackRequest(t, false) // plain HTTP, but Secure forced
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), session)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	cookies := rec.Result().Cookies()

	access := findCookie(cookies, types.AccessTokenCookieName)
	require.NotNil(t, access, "access cookie must be set")
	assert.Equal(t, 1800, access.MaxAge, "access cookie MaxAge = AccessTTL seconds")
	assert.True(t, access.Secure, "Secure forced even on plain HTTP")
	assert.Equal(t, http.SameSiteStrictMode, access.SameSite)

	refresh := findCookie(cookies, types.RefreshTokenCookieName)
	require.NotNil(t, refresh, "refresh cookie must be set")
	assert.Equal(t, 7200, refresh.MaxAge, "refresh cookie MaxAge = RefreshTTL seconds")
	assert.True(t, refresh.Secure)
	assert.Equal(t, http.SameSiteStrictMode, refresh.SameSite)
}

func TestCallback_CookieDefaultsReproduceLegacy(t *testing.T) {
	provider := &fakeProvider{token: &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}}

	// Plain HTTP with auto Secure => not Secure (legacy isSecureRequest behavior).
	rec, req, store := uiCallbackRequest(t, false)
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), defaultSession())
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	cookies := rec.Result().Cookies()

	access := findCookie(cookies, types.AccessTokenCookieName)
	require.NotNil(t, access)
	assert.Equal(t, 3600, access.MaxAge, "legacy access cookie MaxAge = 3600")
	assert.False(t, access.Secure, "auto Secure off on plain HTTP")
	assert.Equal(t, http.SameSiteLaxMode, access.SameSite)

	refresh := findCookie(cookies, types.RefreshTokenCookieName)
	require.NotNil(t, refresh)
	assert.Equal(t, 30*24*3600, refresh.MaxAge, "legacy refresh cookie MaxAge = 2592000")
	assert.False(t, refresh.Secure)
	assert.Equal(t, http.SameSiteLaxMode, refresh.SameSite)

	// Token DB expiries and grant expiry reflect the defaults.
	require.NotNil(t, store.storedToken)
	accessTTL := time.Until(store.storedToken.ExpiresAt)
	assert.InDelta(t, time.Hour.Seconds(), accessTTL.Seconds(), 60, "access token DB expiry ~1h")
	refreshTTL := time.Until(store.storedToken.RefreshTokenExpiresAt)
	assert.InDelta(t, (720 * time.Hour).Seconds(), refreshTTL.Seconds(), 60, "refresh token DB expiry ~720h")

	require.NotNil(t, store.storedGrant)
	grantTTL := store.storedGrant.ExpiresAt - store.storedGrant.CreatedAt
	assert.Equal(t, int64(2592000), grantTTL, "grant expiry mirrors refresh (2592000s)")
}

func TestCallback_CookieSecureAutoOnHTTPS(t *testing.T) {
	provider := &fakeProvider{token: &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}}

	rec, req, store := uiCallbackRequest(t, true) // HTTPS request
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), defaultSession())
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	access := findCookie(rec.Result().Cookies(), types.AccessTokenCookieName)
	require.NotNil(t, access)
	assert.True(t, access.Secure, "auto Secure on HTTPS request")
}

// TestCallback_CookieSecureAutoTrustForwarded verifies that in auto mode the
// cookie Secure flag respects the trust-forwarded policy: a spoofed
// X-Forwarded-Proto: https (no TLS) flips Secure on only when forwarded headers
// are trusted, and is ignored when they are not.
func TestCallback_CookieSecureAutoTrustForwarded(t *testing.T) {
	newReq := func() (*httptest.ResponseRecorder, *http.Request, *fakeStore) {
		rec, req, store := uiCallbackRequest(t, false) // plain HTTP, no TLS
		req.Header.Set("X-Forwarded-Proto", "https")   // client-supplied (spoofable)
		return rec, req, store
	}

	t.Run("Trusted_HonorsForwardedProto", func(t *testing.T) {
		provider := &fakeProvider{token: &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}}
		rec, req, store := newReq()
		req = req.WithContext(handlerutils.WithTrustForwarded(req.Context(), true))
		h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), defaultSession())
		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusFound, rec.Code)
		access := findCookie(rec.Result().Cookies(), types.AccessTokenCookieName)
		require.NotNil(t, access)
		assert.True(t, access.Secure, "trusted: X-Forwarded-Proto: https flips Secure on")
	})

	t.Run("Untrusted_IgnoresSpoofedForwardedProto", func(t *testing.T) {
		provider := &fakeProvider{token: &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}}
		rec, req, store := newReq()
		req = req.WithContext(handlerutils.WithTrustForwarded(req.Context(), false))
		h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), defaultSession())
		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusFound, rec.Code)
		access := findCookie(rec.Result().Cookies(), types.AccessTokenCookieName)
		require.NotNil(t, access)
		assert.False(t, access.Secure, "untrusted: spoofed X-Forwarded-Proto must not flip Secure")
	})
}

// TestCallback_CookieSecureMatchesProxyURLScheme is the peer-review blocker:
// a trusted X-Mcp-Oauth-Proxy-URL: https://ext.example on a plain-HTTP request
// (no TLS, no X-Forwarded-Proto) yields an https base URL, so in auto mode the
// cookie Secure flag MUST also be true. With trust disabled the header is
// ignored and the cookie is not Secure.
func TestCallback_CookieSecureMatchesProxyURLScheme(t *testing.T) {
	newReq := func() (*httptest.ResponseRecorder, *http.Request, *fakeStore) {
		rec, req, store := uiCallbackRequest(t, false) // plain HTTP, no TLS, no XFP
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://ext.example")
		return rec, req, store
	}

	t.Run("Trusted_ProxyURLHTTPS_SecureCookie", func(t *testing.T) {
		provider := &fakeProvider{token: &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}}
		rec, req, store := newReq()
		req = req.WithContext(handlerutils.WithTrustForwarded(req.Context(), true))
		h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), defaultSession())
		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusFound, rec.Code)
		access := findCookie(rec.Result().Cookies(), types.AccessTokenCookieName)
		require.NotNil(t, access)
		assert.True(t, access.Secure, "trusted https X-Mcp-Oauth-Proxy-URL must make the cookie Secure")
		refresh := findCookie(rec.Result().Cookies(), types.RefreshTokenCookieName)
		require.NotNil(t, refresh)
		assert.True(t, refresh.Secure, "trusted https X-Mcp-Oauth-Proxy-URL must make the refresh cookie Secure")
	})

	t.Run("Untrusted_IgnoresProxyURL_NotSecure", func(t *testing.T) {
		provider := &fakeProvider{token: &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}}
		rec, req, store := newReq()
		req = req.WithContext(handlerutils.WithTrustForwarded(req.Context(), false))
		h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), defaultSession())
		h.ServeHTTP(rec, req)

		require.Equal(t, http.StatusFound, rec.Code)
		access := findCookie(rec.Result().Cookies(), types.AccessTokenCookieName)
		require.NotNil(t, access)
		assert.False(t, access.Secure, "untrusted X-Mcp-Oauth-Proxy-URL must not flip Secure on")
	})
}

// TestCallback_CookieSecureMatchesHTTPProxyURLOverTLS is BLOCKER 1 at the
// callback level: a TLS request (uiCallbackRequest secure) carrying a trusted
// http:// X-Mcp-Oauth-Proxy-URL declares an http external URL, so the cookie
// Secure flag MUST be false to match the http base URL GetBaseURL returns.
func TestCallback_CookieSecureMatchesHTTPProxyURLOverTLS(t *testing.T) {
	provider := &fakeProvider{token: &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}}
	rec, req, store := uiCallbackRequest(t, true) // TLS request
	req.Header.Set("X-Mcp-Oauth-Proxy-URL", "http://ext.example")
	req = req.WithContext(handlerutils.WithTrustForwarded(req.Context(), true))
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), defaultSession())
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	access := findCookie(rec.Result().Cookies(), types.AccessTokenCookieName)
	require.NotNil(t, access)
	assert.False(t, access.Secure, "trusted http X-Mcp-Oauth-Proxy-URL over TLS => http base URL => cookie NOT Secure")
	refresh := findCookie(rec.Result().Cookies(), types.RefreshTokenCookieName)
	require.NotNil(t, refresh)
	assert.False(t, refresh.Secure, "refresh cookie must also be NOT Secure")
}

func TestCallback_TokenDBExpiryReflectsCustomConfig(t *testing.T) {
	provider := &fakeProvider{token: &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}}

	session, err := types.ResolveSessionConfig(&types.Config{CookieExpire: "15m", CookieRefresh: "48h"})
	require.NoError(t, err)

	rec, req, store := uiCallbackRequest(t, true)
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t), session)
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	require.NotNil(t, store.storedToken)
	assert.InDelta(t, (15 * time.Minute).Seconds(), time.Until(store.storedToken.ExpiresAt).Seconds(), 30)
	assert.InDelta(t, (48 * time.Hour).Seconds(), time.Until(store.storedToken.RefreshTokenExpiresAt).Seconds(), 30)

	require.NotNil(t, store.storedGrant)
	assert.Equal(t, int64((48 * time.Hour).Seconds()), store.storedGrant.ExpiresAt-store.storedGrant.CreatedAt)
}
