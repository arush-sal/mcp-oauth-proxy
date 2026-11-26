package db

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestGrantRedirectURIRoundTrip: the authorize-time redirect_uri survives
// StoreGrant/GetGrant.
func TestGrantRedirectURIRoundTrip(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().Unix()
	require.NoError(t, store.StoreGrant(&types.Grant{
		ID: "g1", ClientID: "c1", UserID: "u1", CreatedAt: now, ExpiresAt: now + 600,
		RedirectURI: "http://127.0.0.1:5000/cb",
	}))
	got, err := store.GetGrant("g1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:5000/cb", got.RedirectURI)
}

// legacyGrant is the grants table as it existed before redirect_uri was added.
type legacyGrant struct {
	ID        string `gorm:"primaryKey"`
	ClientID  string `gorm:"not null;index"`
	UserID    string `gorm:"not null;index"`
	CreatedAt int64  `gorm:"not null"`
	ExpiresAt int64  `gorm:"not null"`
}

func (legacyGrant) TableName() string { return "grants" }

// TestGrantRedirectURIMigratesExistingDB: opening a pre-upgrade database adds
// the column and existing rows read back with an empty RedirectURI.
func TestGrantRedirectURIMigratesExistingDB(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "legacy.db")
	old, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, old.AutoMigrate(&legacyGrant{}))
	now := time.Now().Unix()
	require.NoError(t, old.Create(&legacyGrant{ID: "g1", ClientID: "c1", UserID: "u1", CreatedAt: now, ExpiresAt: now + 600}).Error)
	sqlDB, err := old.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	store, err := New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	got, err := store.GetGrant("g1", "u1")
	require.NoError(t, err)
	assert.Empty(t, got.RedirectURI)
}
