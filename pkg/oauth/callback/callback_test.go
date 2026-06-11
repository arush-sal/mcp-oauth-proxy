package callback

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	token *oauth2.Token
}

func (p *fakeProvider) GetAuthorizationURL(string, string, string, string) string { return "" }
func (p *fakeProvider) GetAuthorizationURLWithPKCE(string, string, string, string, string) string {
	return ""
}
func (p *fakeProvider) ExchangeCodeForToken(context.Context, string, string, string, string) (*oauth2.Token, error) {
	return p.token, nil
}
func (p *fakeProvider) GetUserInfo(context.Context, string) (*providers.UserInfo, error) {
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

	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier)

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

	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier)

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
	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", nil)

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

	h := NewHandler(store, provider, testEncryptionKey, "client", "secret", "", "", verifier)

	rec, req := newCallbackRequest(t)
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Nil(t, store.storedGrant, "no grant should be stored when id_token verification fails")
}
