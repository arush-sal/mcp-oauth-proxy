package db

import (
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore (db-package isolated SQLite store helper) is defined in
// revoke_by_grant_test.go and reused here.

// TestGetClientRejectsExpired proves the authorize/token client lookup
// (GetClient) treats an expired DCR client as not-found, while a within-TTL
// client and a never-expiring (ExpiresAt=0) client both resolve. This is the
// M1 "expired client_id is invalid_client" requirement.
func TestGetClientRejectsExpired(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()

	require.NoError(t, store.StoreClient(&types.ClientInfo{
		ClientID:  "expired",
		Dynamic:   true,
		ExpiresAt: now.Add(-time.Minute).Unix(),
	}))
	require.NoError(t, store.StoreClient(&types.ClientInfo{
		ClientID:  "valid",
		Dynamic:   true,
		ExpiresAt: now.Add(time.Hour).Unix(),
	}))
	require.NoError(t, store.StoreClient(&types.ClientInfo{
		ClientID:  "never",
		Dynamic:   true,
		ExpiresAt: 0,
	}))

	_, err := store.GetClient("expired")
	require.Error(t, err, "an expired client must be treated as not found")

	got, err := store.GetClient("valid")
	require.NoError(t, err)
	assert.Equal(t, "valid", got.ClientID)

	got, err = store.GetClient("never")
	require.NoError(t, err)
	assert.Equal(t, "never", got.ClientID)
}

// TestCleanupExpiredClients proves the GC deletes only expired DCR clients and
// leaves valid + never-expiring + statically provisioned clients intact.
func TestCleanupExpiredClients(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()

	require.NoError(t, store.StoreClient(&types.ClientInfo{ClientID: "expired1", Dynamic: true, ExpiresAt: now.Add(-time.Hour).Unix()}))
	require.NoError(t, store.StoreClient(&types.ClientInfo{ClientID: "expired2", Dynamic: true, ExpiresAt: now.Add(-time.Second).Unix()}))
	require.NoError(t, store.StoreClient(&types.ClientInfo{ClientID: "valid", Dynamic: true, ExpiresAt: now.Add(time.Hour).Unix()}))
	require.NoError(t, store.StoreClient(&types.ClientInfo{ClientID: "never", Dynamic: true, ExpiresAt: 0}))
	// A statically provisioned client must never be GC'd, even with a stale
	// expiry that should not have been set on it.
	require.NoError(t, store.StoreClient(&types.ClientInfo{ClientID: "static", Dynamic: false, ExpiresAt: now.Add(-time.Hour).Unix()}))

	require.NoError(t, store.CleanupExpiredClients())

	// Expired DCR clients gone.
	_, err := store.rawGetClient("expired1")
	assert.Error(t, err)
	_, err = store.rawGetClient("expired2")
	assert.Error(t, err)

	// Valid, never-expiring, and static clients survive.
	for _, id := range []string{"valid", "never", "static"} {
		_, err := store.rawGetClient(id)
		assert.NoError(t, err, "client %q must survive GC", id)
	}
}

// TestCountDynamicClients proves the cap query counts only Dynamic clients and
// is unaffected by statically provisioned ones.
func TestCountDynamicClients(t *testing.T) {
	store := newTestStore(t)

	n, err := store.CountDynamicClients()
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)

	require.NoError(t, store.StoreClient(&types.ClientInfo{ClientID: "d1", Dynamic: true}))
	require.NoError(t, store.StoreClient(&types.ClientInfo{ClientID: "d2", Dynamic: true}))
	require.NoError(t, store.StoreClient(&types.ClientInfo{ClientID: "s1", Dynamic: false}))

	n, err = store.CountDynamicClients()
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "only Dynamic clients are counted against the cap")
}
