package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeIDToken builds an UNSIGNED (alg=none) JWT carrying the given exp. The
// forwarding staleness check parses exp WITHOUT verification (the token was
// already verified when stored), so an unsigned token is sufficient for tests.
func makeIDToken(t *testing.T, exp time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body, err := json.Marshal(map[string]any{
		"sub": "user123",
		"exp": exp.Unix(),
	})
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(body)
	return header + "." + payload + "."
}

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
	validIDToken := makeIDToken(t, time.Now().Add(1*time.Hour))
	expiredIDToken := makeIDToken(t, time.Now().Add(-1*time.Hour))

	baseProps := func() map[string]any {
		return map[string]any{
			"user_id":      "user123",
			"email":        "user@example.com",
			"name":         "John Doe",
			"access_token": "access-abc",
			"id_token":     validIDToken,
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

		assert.Equal(t, "Bearer "+validIDToken, header.Get("Authorization"))
		assert.Empty(t, header.Get("X-Id-Token"))
	})

	t.Run("IDTokenToCustomHeader", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{IDTokenHeader: "X-Id-Token"})
		header := make(http.Header)
		p.setHeaders(header, baseProps())

		assert.Equal(t, validIDToken, header.Get("X-Id-Token"))
		assert.Empty(t, header.Get("Authorization"))
	})

	t.Run("ExpiredIDTokenNotForwardedAuthorization", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{AuthorizationHeaderToken: "id_token"})
		props := baseProps()
		props["id_token"] = expiredIDToken
		header := make(http.Header)
		p.setHeaders(header, props)

		assert.Empty(t, header.Get("Authorization"))
	})

	t.Run("ExpiredIDTokenNotForwardedCustomHeader", func(t *testing.T) {
		p := newForwardProxy(t, &types.Config{IDTokenHeader: "X-Id-Token"})
		props := baseProps()
		props["id_token"] = expiredIDToken
		header := make(http.Header)
		p.setHeaders(header, props)

		assert.Empty(t, header.Get("X-Id-Token"))
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
		props["id_token"] = expiredIDToken
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
		props["id_token"] = expiredIDToken
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
		props["id_token"] = expiredIDToken
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

// TestForwardingTokenExpiry exercises the staleness helper directly.
func TestForwardingTokenExpiry(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		assert.False(t, idTokenExpired(makeIDToken(t, time.Now().Add(time.Hour))))
	})
	t.Run("Expired", func(t *testing.T) {
		assert.True(t, idTokenExpired(makeIDToken(t, time.Now().Add(-time.Hour))))
	})
	t.Run("Garbage", func(t *testing.T) {
		assert.True(t, idTokenExpired("not-a-jwt"))
	})
	t.Run("Empty", func(t *testing.T) {
		assert.True(t, idTokenExpired(""))
	})
}
