package db

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore builds an isolated SQLite-backed Store in a temp directory.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "test.db")
	store, err := New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestRevokeTokensByGrant verifies that revoking by grant ID marks EVERY token
// row for that grant revoked (the whole session), while leaving other grants'
// tokens untouched (BLOCKER 2).
func TestRevokeTokensByGrant(t *testing.T) {
	store := newTestStore(t)

	// Two token pairs for the same grant (e.g. after a refresh rotation).
	require.NoError(t, store.StoreToken(&types.TokenData{
		AccessToken:  "a1",
		RefreshToken: "r1",
		ClientID:     "c", UserID: "u", GrantID: "grant-A",
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	require.NoError(t, store.StoreToken(&types.TokenData{
		AccessToken:  "a2",
		RefreshToken: "r2",
		ClientID:     "c", UserID: "u", GrantID: "grant-A",
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	// A token belonging to a different grant must NOT be revoked.
	require.NoError(t, store.StoreToken(&types.TokenData{
		AccessToken:  "a3",
		RefreshToken: "r3",
		ClientID:     "c", UserID: "u", GrantID: "grant-B",
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	require.NoError(t, store.RevokeTokensByGrant("grant-A"))

	// Both grant-A access tokens are revoked.
	tok1, err := store.GetToken("a1")
	require.NoError(t, err)
	assert.True(t, tok1.Revoked, "a1 should be revoked")
	tok2, err := store.GetToken("a2")
	require.NoError(t, err)
	assert.True(t, tok2.Revoked, "a2 should be revoked")

	// grant-B is untouched.
	tok3, err := store.GetToken("a3")
	require.NoError(t, err)
	assert.False(t, tok3.Revoked, "a3 (other grant) must stay live")
}
