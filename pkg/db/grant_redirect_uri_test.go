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

// legacyGrant is types.Grant exactly as it was before RedirectURI was added.
type legacyGrant struct {
	ID                  string            `gorm:"primaryKey" json:"id"`
	ClientID            string            `gorm:"not null;index" json:"client_id"`
	UserID              string            `gorm:"not null;index" json:"user_id"`
	Scope               types.StringSlice `gorm:"type:text" json:"scope"`
	Metadata            types.JSON        `gorm:"type:text" json:"metadata"`
	Props               types.JSON        `gorm:"type:text" json:"props"`
	CreatedAt           int64             `gorm:"not null" json:"created_at"`
	ExpiresAt           int64             `gorm:"not null" json:"expires_at"`
	CodeChallenge       string            `json:"code_challenge,omitempty"`
	CodeChallengeMethod string            `json:"code_challenge_method,omitempty"`
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
	legacy := &legacyGrant{
		ID: "g1", ClientID: "c1", UserID: "u1",
		Scope:               types.StringSlice{"openid", "email"},
		Metadata:            types.JSON{"provider": "test"},
		Props:               types.JSON{"email": "u@example.com"},
		CreatedAt:           now,
		ExpiresAt:           now + 600,
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
	}
	require.NoError(t, old.Create(legacy).Error)
	sqlDB, err := old.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	store, err := New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	got, err := store.GetGrant("g1", "u1")
	require.NoError(t, err)
	assert.Empty(t, got.RedirectURI)
	assert.Equal(t, legacy.ClientID, got.ClientID)
	assert.Equal(t, legacy.Scope, got.Scope)
	assert.Equal(t, legacy.Metadata, got.Metadata)
	assert.Equal(t, legacy.Props, got.Props)
	assert.Equal(t, legacy.CreatedAt, got.CreatedAt)
	assert.Equal(t, legacy.ExpiresAt, got.ExpiresAt)
	assert.Equal(t, legacy.CodeChallenge, got.CodeChallenge)
	assert.Equal(t, legacy.CodeChallengeMethod, got.CodeChallengeMethod)
}
