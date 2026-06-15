package authorize

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// fakeStore is an in-memory AuthorizationStore for authorize tests.
type fakeStore struct {
	client *types.ClientInfo
	stored map[string]map[string]any
}

func (s *fakeStore) GetClient(string) (*types.ClientInfo, error) { return s.client, nil }
func (s *fakeStore) StoreAuthRequest(key string, data map[string]any) error {
	if s.stored == nil {
		s.stored = map[string]map[string]any{}
	}
	s.stored[key] = data
	return nil
}

// mockProvider satisfies providers.Provider for the authorize handler.
type mockProvider struct{}

func (mockProvider) GetAuthorizationURL(clientID, redirectURI, scope, state string) string {
	return "https://idp.example/auth?state=" + state
}
func (mockProvider) GetAuthorizationURLWithPKCE(clientID, redirectURI, scope, state, codeChallenge string) string {
	return "https://idp.example/auth?state=" + state
}
func (mockProvider) ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*oauth2.Token, error) {
	return nil, nil
}
func (mockProvider) GetUserInfo(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	return nil, nil
}
func (mockProvider) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret string) (*oauth2.Token, error) {
	return nil, nil
}
func (mockProvider) GetName() string { return "mock" }

func newAuthorizeRequest(clientID, redirectURI, challenge, method string) *http.Request {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid")
	if challenge != "" {
		q.Set("code_challenge", challenge)
	}
	if method != "" {
		q.Set("code_challenge_method", method)
	}
	return httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
}

func newHandlerFor(client *types.ClientInfo) (http.Handler, *fakeStore) {
	store := &fakeStore{client: client}
	h := NewHandler(store, mockProvider{}, []string{"openid"}, "upstream-id", "upstream-secret", "/oauth")
	return h, store
}

const redirectURI = "https://app.example/cb"

// TestAuthorizePublicClientRequiresS256 enforces the H1 Fix 2 authorize-side
// requirement: a public client (token_endpoint_auth_method == "none") must send
// a code_challenge with method S256. Missing challenge or method=plain is
// rejected with invalid_request; a valid S256 challenge proceeds (302 redirect).
func TestAuthorizePublicClientRequiresS256(t *testing.T) {
	publicClient := &types.ClientInfo{
		ClientID:                "public",
		TokenEndpointAuthMethod: "none",
		RedirectUris:            []string{redirectURI},
	}

	t.Run("missing challenge rejected", func(t *testing.T) {
		h, _ := newHandlerFor(publicClient)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newAuthorizeRequest("public", redirectURI, "", ""))
		require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_request")
	})

	t.Run("plain method rejected", func(t *testing.T) {
		h, _ := newHandlerFor(publicClient)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newAuthorizeRequest("public", redirectURI, "abc123challenge", "plain"))
		require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_request")
	})

	t.Run("valid S256 proceeds", func(t *testing.T) {
		h, store := newHandlerFor(publicClient)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newAuthorizeRequest("public", redirectURI, "abc123challenge", "S256"))
		require.Equal(t, http.StatusFound, w.Code, "body: %s", w.Body.String())
		assert.Len(t, store.stored, 1)
	})
}

// TestAuthorizeConfidentialClientChallengeOptional proves confidential clients
// (those with a client secret) keep the pre-H1 behavior: a missing
// code_challenge is still allowed.
func TestAuthorizeConfidentialClientChallengeOptional(t *testing.T) {
	confidentialClient := &types.ClientInfo{
		ClientID:                "confidential",
		ClientSecret:            "shh-secret",
		TokenEndpointAuthMethod: "client_secret_post",
		RedirectUris:            []string{redirectURI},
	}
	h, store := newHandlerFor(confidentialClient)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAuthorizeRequest("confidential", redirectURI, "", ""))
	require.Equal(t, http.StatusFound, w.Code, "body: %s", w.Body.String())
	assert.Len(t, store.stored, 1)
}
