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
}

func (s *fakeStore) StoreGrant(grant *types.Grant) error {
	s.storedGrant = grant
	return nil
}
func (s *fakeStore) StoreAuthCode(string, string, string) error { return nil }
func (s *fakeStore) GetAuthRequest(string) (map[string]any, error) {
	return s.authRequest, nil
}
func (s *fakeStore) DeleteAuthRequest(string) error    { return nil }
func (s *fakeStore) StoreToken(*types.TokenData) error { return nil }

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

	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, allowAny(t))

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

	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, allowAny(t))

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil, allowAny(t))

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

	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, allowAny(t))

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a)

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a)

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a)

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a)

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, allowAny(t))

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a)

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a)

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier, a)

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, store.storedGrant)
}
