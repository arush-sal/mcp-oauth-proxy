package authz

import (
	"encoding/json"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityFromStoredProps(t *testing.T) {
	t.Run("nil props", func(t *testing.T) {
		assert.Equal(t, Identity{}, IdentityFromStoredProps(nil))
	})

	t.Run("from id_token_claims", func(t *testing.T) {
		claims := idtoken.Claims{
			Subject:       "sub-1",
			Email:         "user@example.com",
			EmailVerified: true,
			Groups:        []string{"admins"},
			HostedDomain:  "corp.test",
		}
		b, err := json.Marshal(&claims)
		require.NoError(t, err)
		props := map[string]any{"id_token_claims": string(b)}

		id := IdentityFromStoredProps(props)
		assert.Equal(t, "user@example.com", id.Email)
		assert.True(t, id.EmailVerified)
		assert.Equal(t, []string{"admins"}, id.Groups)
		assert.Equal(t, "corp.test", id.HostedDomain)
	})

	t.Run("falls back to stored email with stored verified flag", func(t *testing.T) {
		props := map[string]any{"email": "user@example.com", "email_verified": true}
		id := IdentityFromStoredProps(props)
		assert.Equal(t, "user@example.com", id.Email)
		assert.True(t, id.EmailVerified)
	})

	t.Run("stored unverified email is not treated as verified", func(t *testing.T) {
		// BLOCKER 1: a stored email whose verified flag is false (or missing) must
		// NOT be promoted to verified on refresh re-check.
		props := map[string]any{"email": "user@example.com", "email_verified": false}
		id := IdentityFromStoredProps(props)
		assert.Equal(t, "user@example.com", id.Email)
		assert.False(t, id.EmailVerified, "unverified stored email must stay unverified")
	})

	t.Run("missing email_verified defaults to false", func(t *testing.T) {
		props := map[string]any{"email": "user@example.com"}
		id := IdentityFromStoredProps(props)
		assert.Equal(t, "user@example.com", id.Email)
		assert.False(t, id.EmailVerified, "missing email_verified must default to false")
	})

	t.Run("id_token claims verified state preferred over stored top-level", func(t *testing.T) {
		// id_token says verified=false; even if a stored top-level email_verified
		// were true, the claims-derived state wins for the claims email.
		claims := idtoken.Claims{Email: "token@example.com", EmailVerified: false}
		b, _ := json.Marshal(&claims)
		props := map[string]any{
			"id_token_claims": string(b),
			"email":           "userinfo@example.com",
			"email_verified":  true,
		}
		id := IdentityFromStoredProps(props)
		assert.Equal(t, "token@example.com", id.Email)
		assert.False(t, id.EmailVerified, "id_token claims verified state must win")
	})

	t.Run("id_token email wins over stored email", func(t *testing.T) {
		claims := idtoken.Claims{Email: "token@example.com", EmailVerified: true}
		b, _ := json.Marshal(&claims)
		props := map[string]any{
			"id_token_claims": string(b),
			"email":           "userinfo@example.com",
		}
		id := IdentityFromStoredProps(props)
		assert.Equal(t, "token@example.com", id.Email)
	})
}

func TestAuthorizeStoredProps(t *testing.T) {
	verified := func() map[string]any {
		claims := idtoken.Claims{Email: "user@example.com", EmailVerified: true}
		b, _ := json.Marshal(&claims)
		return map[string]any{"id_token_claims": string(b)}
	}

	t.Run("nil authorizer denies", func(t *testing.T) {
		// CONCERN 1: nil authorizer must fail closed.
		assert.ErrorIs(t, AuthorizeStoredProps(nil, verified()), ErrDenied)
	})

	t.Run("allows matching identity", func(t *testing.T) {
		a, err := New(Config{EmailDomains: []string{"example.com"}})
		require.NoError(t, err)
		assert.NoError(t, AuthorizeStoredProps(a, verified()))
	})

	t.Run("denies non-matching identity", func(t *testing.T) {
		a, err := New(Config{EmailDomains: []string{"other.com"}})
		require.NoError(t, err)
		assert.ErrorIs(t, AuthorizeStoredProps(a, verified()), ErrDenied)
	})
}
