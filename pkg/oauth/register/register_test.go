package register

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// CountDynamicClients counts the DCR-registered (Dynamic) clients, mirroring
// the efficient COUNT the real store performs for the cap check.
func (f *fakeStore) CountDynamicClients() (int64, error) {
	var n int64
	for _, c := range f.clients {
		if c.Dynamic {
			n++
		}
	}
	return n, nil
}

const registerBody = `{"redirect_uris":["https://client.example.com/callback"],"client_name":"Test Client","token_endpoint_auth_method":"none"}`

// TestRegisterEnabledStoresClient verifies the enabled handler registers and
// persists a client.
func TestRegisterEnabledStoresClient(t *testing.T) {
	store := newFakeStore()
	h := NewHandler(store, true, 0, 0)

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
	h := NewHandler(store, false, 0, 0)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", strings.NewReader(registerBody))
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "dynamic client registration is disabled")
	assert.Empty(t, store.clients, "no client should be stored when DCR is disabled")
}

// TestRegisterRedirectURIValidation enforces the H1 DCR redirect_uri allowlist:
// only https:// (any host) and loopback http (127.0.0.1 / localhost / [::1]) are
// accepted. Fragments, embedded credentials, and wildcards are always rejected,
// and non-loopback http:// is rejected. A rejection must return 400 with an
// invalid_redirect_uri error (RFC 7591) and must not store the client.
func TestRegisterRedirectURIValidation(t *testing.T) {
	cases := []struct {
		name     string
		uri      string
		accepted bool
	}{
		{"https any host accepted", "https://app.example/cb", true},
		{"loopback ipv4 with port accepted", "http://127.0.0.1:1234/cb", true},
		{"loopback localhost accepted", "http://localhost/cb", true},
		{"loopback ipv6 accepted", "http://[::1]/cb", true},
		{"non-loopback http rejected", "http://evil.com/cb", false},
		{"fragment rejected", "https://app/cb#frag", false},
		{"embedded credentials rejected", "https://user:pass@app/cb", false},
		{"wildcard rejected", "https://*.evil/cb", false},
		// Loopback-as-subdomain must not be treated as loopback.
		{"loopback as subdomain rejected", "http://127.0.0.1.evil.com", false},
		// Obfuscated loopback forms (hex octet, decimal integer) are not the
		// allowlisted literal "127.0.0.1" and must be rejected.
		{"hex obfuscated loopback rejected", "http://0x7f.0.0.1", false},
		{"decimal integer loopback rejected", "http://2130706433", false},
		// Scheme-relative URI has an empty scheme; must be rejected.
		{"scheme-relative rejected", "//evil.com/path", false},
		// Hostless https (Blocker 1) must be rejected.
		{"hostless https rejected", "https:///path", false},
		// Private-use URI schemes (RFC 8252 §7.1) for native apps are accepted:
		// authority form (Cursor), no-authority form, and reverse-DNS form.
		{"private-use scheme authority accepted", "cursor://anysphere.cursor-mcp/oauth/callback", true},
		{"private-use scheme no-authority accepted", "com.example.app:/oauth/callback", true},
		{"reverse-dns private-use scheme accepted", "com.googleusercontent.apps.123:/cb", true},
		// Dangerous / non-app schemes are rejected even though they are not http(s).
		{"javascript scheme rejected", "javascript:alert(1)", false},
		{"data scheme rejected", "data:text/html,evil", false},
		{"file scheme rejected", "file:///etc/passwd", false},
		{"mailto scheme rejected", "mailto:a@b.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			h := NewHandler(store, true, 0, 0)

			// Build the body with json.Marshal so backslash-containing or
			// otherwise special URIs are not accidentally malformed by string
			// concatenation.
			bodyBytes, err := json.Marshal(map[string]any{
				"redirect_uris":              []string{tc.uri},
				"client_name":                "Test",
				"token_endpoint_auth_method": "none",
			})
			require.NoError(t, err)
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/register", strings.NewReader(string(bodyBytes)))
			h.ServeHTTP(w, req)

			if tc.accepted {
				require.Equal(t, http.StatusOK, w.Code, "uri %q should be accepted, body: %s", tc.uri, w.Body.String())
				assert.Len(t, store.clients, 1)
				return
			}
			require.Equal(t, http.StatusBadRequest, w.Code, "uri %q should be rejected", tc.uri)
			assert.Contains(t, w.Body.String(), "invalid_redirect_uri")
			assert.Empty(t, store.clients, "rejected redirect URI must not store a client")
		})
	}
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
	h := NewHandler(store, false, 0, 0)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/register", strings.NewReader(registerBody))
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)

	// The pre-existing client is untouched and still resolvable.
	got, ok := store.GetClient("pre-existing-client")
	require.True(t, ok, "pre-existing client must still resolve when DCR is disabled")
	assert.Equal(t, existing.ClientSecret, got.ClientSecret)
}

// TestRegisterCapEnforced proves the M1 cap: with a cap of N and N DCR clients
// already present, the (N+1)th /register is rejected and NOT stored; under the
// cap a registration succeeds and is marked Dynamic so it counts toward the cap.
func TestRegisterCapEnforced(t *testing.T) {
	store := newFakeStore()
	const cap = 2
	h := NewHandler(store, true, cap, 0)

	register := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", strings.NewReader(registerBody))
		h.ServeHTTP(w, req)
		return w
	}

	// First two registrations succeed and are stored as Dynamic clients.
	require.Equal(t, http.StatusOK, register().Code)
	require.Equal(t, http.StatusOK, register().Code)
	assert.Len(t, store.clients, cap, "both under-cap registrations should be stored")
	for _, c := range store.clients {
		assert.True(t, c.Dynamic, "DCR-registered client must be marked Dynamic")
	}

	// The third exceeds the cap: rejected, not stored.
	w := register()
	require.Equal(t, http.StatusTooManyRequests, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "limit reached")
	assert.Len(t, store.clients, cap, "over-cap registration must NOT be stored")
}

// TestRegisterCapUnlimited proves a cap of 0 means unlimited (no rejection).
func TestRegisterCapUnlimited(t *testing.T) {
	store := newFakeStore()
	h := NewHandler(store, true, 0, 0)
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", strings.NewReader(registerBody))
		h.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}
	assert.Len(t, store.clients, 5)
}

// TestRegisterTTLStamped proves a configured TTL stamps the stored client with
// a future expiry, and a zero TTL leaves it never-expiring (ExpiresAt=0).
func TestRegisterTTLStamped(t *testing.T) {
	t.Run("ttl set => future expiry", func(t *testing.T) {
		store := newFakeStore()
		h := NewHandler(store, true, 0, time.Hour)
		before := time.Now().Unix()

		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", strings.NewReader(registerBody))
		h.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		require.Len(t, store.clients, 1)
		for _, c := range store.clients {
			assert.True(t, c.Dynamic)
			assert.GreaterOrEqual(t, c.ExpiresAt, before+int64(time.Hour.Seconds())-5)
		}
	})

	t.Run("ttl zero => never expires", func(t *testing.T) {
		store := newFakeStore()
		h := NewHandler(store, true, 0, 0)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", strings.NewReader(registerBody))
		h.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		require.Len(t, store.clients, 1)
		for _, c := range store.clients {
			assert.Equal(t, int64(0), c.ExpiresAt, "TTL=0 must leave the client never-expiring")
		}
	})
}
