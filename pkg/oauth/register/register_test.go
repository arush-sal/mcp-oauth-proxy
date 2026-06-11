package register

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStore is an in-memory ClientStore that also supports lookup, so we can
// prove that a previously-stored client remains retrievable (the path the
// authorize/token flows use) even when DCR is disabled.
type fakeStore struct {
	clients map[string]*types.ClientInfo
}

func newFakeStore() *fakeStore {
	return &fakeStore{clients: map[string]*types.ClientInfo{}}
}

func (f *fakeStore) StoreClient(client *types.ClientInfo) error {
	f.clients[client.ClientID] = client
	return nil
}

func (f *fakeStore) GetClient(clientID string) (*types.ClientInfo, bool) {
	c, ok := f.clients[clientID]
	return c, ok
}

const registerBody = `{"redirect_uris":["https://client.example.com/callback"],"client_name":"Test Client","token_endpoint_auth_method":"none"}`

// TestRegisterEnabledStoresClient verifies the enabled handler registers and
// persists a client.
func TestRegisterEnabledStoresClient(t *testing.T) {
	store := newFakeStore()
	h := NewHandler(store, true)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", strings.NewReader(registerBody))
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "client_id")
	assert.Len(t, store.clients, 1, "client should have been stored")
}

// TestRegisterDisabledForbidden verifies the disabled handler rejects with 403
// and an OAuthError body, and does NOT store anything.
func TestRegisterDisabledForbidden(t *testing.T) {
	store := newFakeStore()
	h := NewHandler(store, false)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", strings.NewReader(registerBody))
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "dynamic client registration is disabled")
	assert.Empty(t, store.clients, "no client should be stored when DCR is disabled")
}

// TestExistingClientStillResolvesWhenDisabled proves that a pre-existing /
// already-registered client (in the store) is still retrievable via GetClient
// (the lookup authorize/token rely on) even though DCR registration is off.
func TestExistingClientStillResolvesWhenDisabled(t *testing.T) {
	store := newFakeStore()
	// Simulate a client registered earlier (e.g. before DCR was disabled, or a
	// statically provisioned one).
	existing := &types.ClientInfo{
		ClientID:     "pre-existing-client",
		ClientSecret: "secret",
		RedirectUris: []string{"https://client.example.com/callback"},
	}
	require.NoError(t, store.StoreClient(existing))

	// DCR is disabled: /register is forbidden.
	h := NewHandler(store, false)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", strings.NewReader(registerBody))
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)

	// The pre-existing client is untouched and still resolvable.
	got, ok := store.GetClient("pre-existing-client")
	require.True(t, ok, "pre-existing client must still resolve when DCR is disabled")
	assert.Equal(t, existing.ClientSecret, got.ClientSecret)
}
