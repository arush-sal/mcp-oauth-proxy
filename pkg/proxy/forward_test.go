package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idTokenValue is an opaque raw id_token string used by the forwarding tests.
// Staleness is no longer decided by parsing this value; it is driven entirely by
// props["id_token_exp"] (the id_token's OWN exp captured at store time), so the
// raw token here can be any non-empty marker.
const idTokenValue = "raw.id.token"

func newForwardProxy(t *testing.T, cfg *types.Config) *OAuthProxy {
	t.Helper()
	if cfg.Mode == "" {
		cfg.Mode = ModeForwardAuth
	}
	p, err := NewOAuthProxy(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestSetHeadersForwarding(t *testing.T) {
	futureExp := time.Now().Add(1 * time.Hour).Unix()
	pastExp := time.Now().Add(-1 * time.Hour).Unix()

	// baseProps carries a valid (future-exp) id_token. Staleness is driven by
	// props["id_token_exp"], not by parsing the raw token.
	baseProps := func() map[string]any {
		return map[string]any{
			"user_id":      "user123",
			"email":        "user@example.com",
			"name":         "John Doe",
			"access_token": "access-abc",
			"id_token":     idTokenValue,
			"id_token_exp": futureExp,
		}
	}

	t.Run("DefaultNone", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{})
		header := make(http.Header)
		p.setHeaders(header, baseProps())

		assert.Empty(t, header.Get("Authorization"))
		assert.Equal(t, "access-abc", header.Get("X-Forwarded-Access-Token"))
		assert.Equal(t, "user@example.com", header.Get("X-Forwarded-Email"))
	})

	t.Run("AccessToken", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{AuthorizationHeaderToken: "access_token"})
		header := make(http.Header)
		p.setHeaders(header, baseProps())

		assert.Equal(t, "Bearer access-abc", header.Get("Authorization"))
		assert.Equal(t, "access-abc", header.Get("X-Forwarded-Access-Token"))
	})

	t.Run("IDTokenToAuthorization", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{AuthorizationHeaderToken: "id_token"})
		header := make(http.Header)
		p.setHeaders(header, baseProps())

		assert.Equal(t, "Bearer "+idTokenValue, header.Get("Authorization"))
		assert.Empty(t, header.Get("X-Id-Token"))
	})

	t.Run("IDTokenToCustomHeader", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{IDTokenHeader: "X-Id-Token"})
		header := make(http.Header)
		p.setHeaders(header, baseProps())

		assert.Equal(t, idTokenValue, header.Get("X-Id-Token"))
		assert.Empty(t, header.Get("Authorization"))
	})

	t.Run("ExpiredIDTokenNotForwardedAuthorization", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{AuthorizationHeaderToken: "id_token"})
		props := baseProps()
		props["id_token_exp"] = pastExp
		header := make(http.Header)
		p.setHeaders(header, props)

		assert.Empty(t, header.Get("Authorization"))
	})

	t.Run("ExpiredIDTokenNotForwardedCustomHeader", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{IDTokenHeader: "X-Id-Token"})
		props := baseProps()
		props["id_token_exp"] = pastExp
		header := make(http.Header)
		p.setHeaders(header, props)

		assert.Empty(t, header.Get("X-Id-Token"))
	})

	t.Run("MissingExpIDTokenNotForwarded", func(t *testing.T) {
		// A stored id_token with NO recorded exp must fail closed (not forwarded),
		// even though the raw token is present.
		p := newForwardProxy(t, &types.Config{AuthorizationHeaderToken: "id_token"})
		props := baseProps()
		delete(props, "id_token_exp")
		header := make(http.Header)
		p.setHeaders(header, props)

		assert.Empty(t, header.Get("Authorization"))
	})

	t.Run("AbsentIDTokenNotForwarded", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{AuthorizationHeaderToken: "id_token"})
		props := baseProps()
		delete(props, "id_token")
		header := make(http.Header)
		p.setHeaders(header, props)

		assert.Empty(t, header.Get("Authorization"))
	})

	t.Run("InboundAuthorizationClearedOnNone", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{})
		header := make(http.Header)
		header.Set("Authorization", "Bearer spoofed-inbound")
		p.setHeaders(header, baseProps())

		// none mode must not leave a spoofed inbound Authorization.
		assert.Empty(t, header.Get("Authorization"))
	})

	t.Run("InboundAuthorizationReplacedOnAccessToken", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{AuthorizationHeaderToken: "access_token"})
		header := make(http.Header)
		header.Set("Authorization", "Bearer spoofed-inbound")
		p.setHeaders(header, baseProps())

		assert.Equal(t, "Bearer access-abc", header.Get("Authorization"))
	})

	t.Run("ExpiredIDTokenClearsSpoofedAuthorization", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{AuthorizationHeaderToken: "id_token"})
		props := baseProps()
		props["id_token_exp"] = pastExp
		header := make(http.Header)
		header.Set("Authorization", "Bearer spoofed-inbound")
		p.setHeaders(header, props)

		// Stale token is not forwarded AND the spoofed value must be gone.
		assert.Empty(t, header.Get("Authorization"))
	})

	t.Run("SpoofedCustomHeaderClearedExpiredIDToken", func(t *testing.T) {
		// A client pre-seeds the configured custom id_token header. With an
		// expired stored id_token nothing valid is forwarded, so the spoofed
		// inbound value must NOT survive into the upstream request.
		p := newForwardProxy(t, &types.Config{IDTokenHeader: "X-Id-Token"})
		props := baseProps()
		props["id_token_exp"] = pastExp
		header := make(http.Header)
		header.Set("X-Id-Token", "spoofed.jwt.value")
		p.setHeaders(header, props)

		assert.Empty(t, header.Get("X-Id-Token"))
	})

	t.Run("SpoofedCustomHeaderClearedAbsentIDToken", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{IDTokenHeader: "X-Id-Token"})
		props := baseProps()
		delete(props, "id_token")
		header := make(http.Header)
		header.Set("X-Id-Token", "spoofed.jwt.value")
		p.setHeaders(header, props)

		assert.Empty(t, header.Get("X-Id-Token"))
	})

	t.Run("SpoofedAuthorizationClearedExpiredIDToken", func(t *testing.T) {
		// id_token policy targeting Authorization with an expired stored token:
		// the spoofed inbound Authorization must be gone.
		p := newForwardProxy(t, &types.Config{AuthorizationHeaderToken: "id_token"})
		props := baseProps()
		props["id_token_exp"] = pastExp
		header := make(http.Header)
		header.Set("Authorization", "Bearer spoofed.jwt.value")
		p.setHeaders(header, props)

		assert.Empty(t, header.Get("Authorization"))
	})
}

func TestValidateForwardingConfig(t *testing.T) {
	testCases := []struct {
		name          string
		authToken     string
		idTokenHeader string
		expectError   bool
		errorContains string
	}{
		{name: "DefaultEmpty", authToken: "", idTokenHeader: "", expectError: false},
		{name: "None", authToken: "none", idTokenHeader: "", expectError: false},
		{name: "AccessToken", authToken: "access_token", idTokenHeader: "", expectError: false},
		{name: "IDToken", authToken: "id_token", idTokenHeader: "", expectError: false},
		{name: "CustomHeaderOnly", authToken: "", idTokenHeader: "X-Id-Token", expectError: false},
		{name: "CustomHeaderWithNone", authToken: "none", idTokenHeader: "X-Id-Token", expectError: false},
		{name: "CustomHeaderWithAccessToken", authToken: "access_token", idTokenHeader: "X-Id-Token", expectError: false},
		{
			name:          "InvalidAuthToken",
			authToken:     "bogus",
			expectError:   true,
			errorContains: "AUTHORIZATION_HEADER_TOKEN",
		},
		{
			name:          "IDTokenAndCustomHeaderAmbiguous",
			authToken:     "id_token",
			idTokenHeader: "X-Id-Token",
			expectError:   true,
			errorContains: "id_token",
		},
		{
			name:          "CustomHeaderAuthorizationWithAccessToken",
			authToken:     "access_token",
			idTokenHeader: "authorization",
			expectError:   true,
			errorContains: "Authorization",
		},
		{
			name:          "CustomHeaderCollidesAccessTokenHeader",
			authToken:     "none",
			idTokenHeader: "x-forwarded-access-token",
			expectError:   true,
			errorContains: "X-Forwarded-Access-Token",
		},
		{
			name:          "CustomHeaderCollidesForwardedUser",
			authToken:     "none",
			idTokenHeader: "X-Forwarded-User",
			expectError:   true,
			errorContains: "X-Forwarded-User",
		},
		{
			name:          "CustomHeaderCollidesForwardedEmail",
			authToken:     "none",
			idTokenHeader: "X-Forwarded-Email",
			expectError:   true,
			errorContains: "X-Forwarded-Email",
		},
		{
			name:          "CustomHeaderCollidesForwardedName",
			authToken:     "none",
			idTokenHeader: "X-Forwarded-Name",
			expectError:   true,
			errorContains: "X-Forwarded-Name",
		},
		{
			name:          "CustomHeaderCollidesForwardedEmailCaseVariant",
			authToken:     "none",
			idTokenHeader: "x-forwarded-email",
			expectError:   true,
			errorContains: "X-Forwarded-Email",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &types.Config{
				Mode:                     ModeForwardAuth,
				AuthorizationHeaderToken: tc.authToken,
				IDTokenHeader:            tc.idTokenHeader,
			}
			_, err := NewOAuthProxy(cfg)
			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestForwardingTokenExpiry exercises the staleness helper directly. Staleness
// is read from props["id_token_exp"] (the id_token's OWN exp, Unix seconds),
// NOT from props["expires_at"] (the access-token expiry). It fails closed for a
// missing/zero/past/wrong-typed exp.
func TestForwardingTokenExpiry(t *testing.T) {
	t.Run("ValidFloat64", func(t *testing.T) {
		// JSON-decoded props deliver numbers as float64.
		assert.False(t, idTokenStale(map[string]any{"id_token_exp": float64(time.Now().Add(time.Hour).Unix())}))
	})
	t.Run("ValidInt64", func(t *testing.T) {
		// In-process props (e.g. forward_auth) may carry an int64.
		assert.True(t, !idTokenStale(map[string]any{"id_token_exp": time.Now().Add(time.Hour).Unix()}))
	})
	t.Run("Expired", func(t *testing.T) {
		assert.True(t, idTokenStale(map[string]any{"id_token_exp": float64(time.Now().Add(-time.Hour).Unix())}))
	})
	t.Run("Missing", func(t *testing.T) {
		assert.True(t, idTokenStale(map[string]any{"id_token": idTokenValue}))
	})
	t.Run("Zero", func(t *testing.T) {
		assert.True(t, idTokenStale(map[string]any{"id_token_exp": float64(0)}))
	})
	t.Run("WrongType", func(t *testing.T) {
		assert.True(t, idTokenStale(map[string]any{"id_token_exp": "not-a-number"}))
	})
	t.Run("IgnoresAccessTokenExpiresAt", func(t *testing.T) {
		// A future access-token expires_at must NOT make a missing id_token_exp
		// look fresh: the two are distinct values.
		assert.True(t, idTokenStale(map[string]any{"expires_at": float64(time.Now().Add(time.Hour).Unix())}))
	})
}
