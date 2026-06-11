package authz

import (
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/stretchr/testify/assert"
)

func TestIdentityFromClaims(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		assert.Equal(t, Identity{}, IdentityFromClaims(nil))
	})
	t.Run("populated", func(t *testing.T) {
		id := IdentityFromClaims(&idtoken.Claims{
			Subject:       "sub-1",
			Email:         "user@example.com",
			EmailVerified: true,
			Groups:        []string{"admins"},
			HostedDomain:  "corp.test",
		})
		assert.Equal(t, "sub-1", id.Subject)
		assert.Equal(t, "user@example.com", id.Email)
		assert.True(t, id.EmailVerified)
		assert.Equal(t, []string{"admins"}, id.Groups)
		assert.Equal(t, "corp.test", id.HostedDomain)
	})
}

func TestMergeUserInfo(t *testing.T) {
	t.Run("fills missing email", func(t *testing.T) {
		id := MergeUserInfo(Identity{Subject: "s"}, "user@example.com", true)
		assert.Equal(t, "user@example.com", id.Email)
		assert.True(t, id.EmailVerified)
	})
	t.Run("does not override id_token email", func(t *testing.T) {
		id := MergeUserInfo(Identity{Email: "token@example.com", EmailVerified: true}, "userinfo@example.com", false)
		assert.Equal(t, "token@example.com", id.Email)
		assert.True(t, id.EmailVerified)
	})
	t.Run("empty userinfo email leaves identity unchanged", func(t *testing.T) {
		id := MergeUserInfo(Identity{Subject: "s"}, "", false)
		assert.Empty(t, id.Email)
	})
}
