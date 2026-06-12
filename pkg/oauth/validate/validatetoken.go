package validate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/authz"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

type TokenValidator struct {
	tokenManager           *tokens.TokenManager
	encryptionKey          []byte
	db                     TokenStore         // Database for refresh operations
	provider               providers.Provider // OAuth provider for generating auth URLs
	routePrefix            string
	clientID               string // OAuth client ID
	clientSecret           string // OAuth client secret
	accessTokenCookieName  string
	refreshTokenCookieName string
	mcpServerID            string
	scopesSupported        []string // Supported OAuth scopes
	mcpPaths               []string
	authorizer             *authz.Authorizer // allowlist, re-checked on refresh
	idTokenVerifier        IDTokenVerifier   // optional, to re-verify a fresh id_token on refresh
	session                types.SessionConfig
}

// IDTokenVerifier verifies an IdP-issued id_token and returns its normalized
// claims. *idtoken.Verifier satisfies this; kept as an interface so it is
// optional and the validator can be unit tested.
type IDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*idtoken.Claims, error)
}

// TokenStore interface for database operations needed by validator
type TokenStore interface {
	GetToken(accessToken string) (*types.TokenData, error)
	GetTokenByRefreshToken(refreshToken string) (*types.TokenData, error)
	StoreToken(token *types.TokenData) error
	RevokeToken(token string) error
	RevokeTokensByGrant(grantID string) error
	StoreAuthRequest(key string, data map[string]any) error
	GetGrant(grantID, userID string) (*types.Grant, error)
}

func NewTokenValidator(tokenManager *tokens.TokenManager, encryptionKey []byte, db TokenStore, provider providers.Provider, routePrefix, clientID, clientSecret, cookieNamePrefix, mcpServerID string, scopesSupported, mcpPaths []string, authorizer *authz.Authorizer, idTokenVerifier IDTokenVerifier, session types.SessionConfig) *TokenValidator {
	return &TokenValidator{
		tokenManager:           tokenManager,
		encryptionKey:          encryptionKey,
		db:                     db,
		provider:               provider,
		routePrefix:            routePrefix,
		clientID:               clientID,
		clientSecret:           clientSecret,
		accessTokenCookieName:  cookieNamePrefix + types.AccessTokenCookieName,
		refreshTokenCookieName: cookieNamePrefix + types.RefreshTokenCookieName,
		mcpServerID:            mcpServerID,
		scopesSupported:        scopesSupported,
		mcpPaths:               mcpPaths,
		authorizer:             authorizer,
		idTokenVerifier:        idTokenVerifier,
		session:                session,
	}
}

func (p *TokenValidator) SetOAuthConfig(provider providers.Provider, clientID, clientSecret string, scopesSupported []string) {
	p.provider = provider
	p.clientID = clientID
	p.clientSecret = clientSecret
	p.scopesSupported = scopesSupported
}

// generatePKCE generates PKCE code verifier and challenge
func generatePKCE() (codeVerifier, codeChallenge string) {
	// Generate a random code verifier (43-128 characters, base64url)
	codeVerifier = encryption.GenerateRandomString(32) // This generates 32 bytes -> ~43 chars in base64

	// Generate code challenge using S256 method
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return codeVerifier, codeChallenge
}

func (p *TokenValidator) WithTokenValidation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			token      string
			fromCookie bool
			authHeader = r.Header.Get("Authorization")
		)
		if authHeader == "" {
			cookie, err := r.Cookie(p.accessTokenCookieName)
			if err == nil && cookie.Value != "" {
				// Decrypt the cookie value
				token, err = encryption.DecryptCookie(p.encryptionKey, cookie.Value)
				if err != nil {
					p.sendUnauthorizedResponse(w, r, "Failed to decrypt token")
					return
				}
				fromCookie = true
			}
		} else {
			// Parse Authorization header
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || parts[1] == "" {
				p.sendUnauthorizedResponse(w, r, "Invalid Authorization header format, expected 'Bearer TOKEN'")
				return
			}

			token = parts[1]
			fromCookie = false
		}

		// Validate token (handles both API keys and JWT/simple tokens)
		tokenInfo, err := p.tokenManager.GetTokenInfoWithContext(r.Context(), token, p.mcpServerID)
		if err != nil {
			p.sendUnauthorizedResponse(w, r, fmt.Sprintf("Invalid or expired token: %v", err))
			return
		}

		// Check if token is within 15 minutes of expiring and attempt refresh if from cookie
		if fromCookie && time.Until(tokenInfo.ExpiresAt) < 15*time.Minute {
			newToken, refreshErr := p.refreshAccessToken(w, r)
			if refreshErr != nil {
				// Authorization was REVOKED during refresh: block the current
				// request immediately, regardless of remaining token validity.
				// refreshAccessToken has already revoked the whole session, so
				// letting the in-flight request finish on the still-valid token
				// would let a revoked user keep access for up to ~15 minutes.
				if errors.Is(refreshErr, authz.ErrDenied) {
					p.sendUnauthorizedResponse(w, r, "Authorization revoked")
					return
				}
				// If token is already expired, refresh is required
				if time.Now().After(tokenInfo.ExpiresAt) {
					p.sendUnauthorizedResponse(w, r, "Token expired and refresh failed")
					return
				}
				// Non-deny (infra) error and token not yet expired: a transient
				// blip must not block the request (CONCERN 2). Log and continue
				// with the current token.
				fmt.Printf("Token refresh failed but token still valid, continuing: %v\n", refreshErr)
			} else {
				// Refresh succeeded, use new token and get updated token info
				token = newToken
				tokenInfo, err = p.tokenManager.GetTokenInfoWithContext(r.Context(), token, p.mcpServerID)
				if err != nil {
					p.sendUnauthorizedResponse(w, r, "Failed to validate refreshed token")
					return
				}
			}
		}

		// Decrypt props if needed before storing in context
		if tokenInfo.Props != nil {
			decryptedProps, err := encryption.DecryptPropsIfNeeded(p.encryptionKey, tokenInfo.Props)
			if err != nil {
				p.sendUnauthorizedResponse(w, r, "Failed to decrypt token data")
				return
			}
			tokenInfo.Props = decryptedProps
		}

		// Store both tokenInfo and the original bearer token string
		ctx := context.WithValue(r.Context(), tokenInfoKey{}, tokenInfo)
		ctx = context.WithValue(ctx, bearerTokenKey{}, token)
		next(w, r.WithContext(ctx))
	}
}

// refreshAccessToken attempts to refresh an access token using the refresh token
// Returns the new access token string, or an error if refresh fails
func (p *TokenValidator) refreshAccessToken(w http.ResponseWriter, r *http.Request) (string, error) {
	// Get refresh token from cookie
	refreshCookie, err := r.Cookie(p.refreshTokenCookieName)
	if err != nil || refreshCookie.Value == "" {
		return "", fmt.Errorf("no refresh token cookie found")
	}

	// Decrypt refresh token
	refreshToken, err := encryption.DecryptCookie(p.encryptionKey, refreshCookie.Value)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	// Validate refresh token and get token data
	tokenData, err := p.db.GetTokenByRefreshToken(refreshToken)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if token is revoked
	if tokenData.Revoked {
		return "", fmt.Errorf("refresh token has been revoked")
	}

	// Re-check the allowlist on every refresh (user decision: authorization is
	// re-evaluated on each token refresh). This internal-token rotation does not
	// contact the IdP, so we re-derive the identity from the stored grant claims.
	// On an actual authorization DENY we revoke the whole session so the
	// cookie/browser path is forced to re-authenticate. On an infrastructure
	// error (grant load/decrypt failure) we fail closed for THIS request only and
	// do NOT revoke the session, so a transient DB blip cannot permanently kill
	// it. Either way we return an error (never a 500) that the caller maps to a
	// 401 / re-auth flow.
	if err := p.reauthorizeStoredGrant(tokenData.GrantID, tokenData.UserID); err != nil {
		if errors.Is(err, authz.ErrDenied) {
			p.revokeGrantTokens(refreshToken, tokenData)
			return "", fmt.Errorf("authorization revoked on refresh: %w", err)
		}
		// Infrastructure error: deny this refresh but keep the session.
		return "", fmt.Errorf("authorization re-check failed on refresh: %w", err)
	}

	// Generate new access token: userId:grantId:accessTokenSecret
	accessTokenSecret := encryption.GenerateRandomString(32)
	newAccessToken := fmt.Sprintf("%s:%s:%s", tokenData.UserID, tokenData.GrantID, accessTokenSecret)

	// Generate new refresh token
	refreshTokenSecret := encryption.GenerateRandomString(32)
	newRefreshToken := fmt.Sprintf("%s:%s:%s", tokenData.UserID, tokenData.GrantID, refreshTokenSecret)

	// Store new token data in database
	newTokenData := &types.TokenData{
		AccessToken:           newAccessToken,
		RefreshToken:          newRefreshToken,
		ClientID:              tokenData.ClientID,
		UserID:                tokenData.UserID,
		GrantID:               tokenData.GrantID,
		Scope:                 tokenData.Scope,
		ExpiresAt:             time.Now().Add(p.session.AccessTTL),  // access token lifetime
		RefreshTokenExpiresAt: time.Now().Add(p.session.RefreshTTL), // refresh token lifetime
		CreatedAt:             time.Now(),
		Revoked:               false,
	}

	if err := p.db.StoreToken(newTokenData); err != nil {
		return "", fmt.Errorf("failed to store new token: %w", err)
	}

	// Determine if request is secure for cookie Secure flag. RequestIsHTTPS is
	// the single source of truth shared with GetBaseURL, so the cookie Secure
	// flag matches the derived base-URL scheme.
	isSecure := p.session.SecureForRequest(handlerutils.RequestIsHTTPS(r))

	// Encrypt and set access token cookie
	encryptedAccessToken, err := encryption.EncryptCookie(p.encryptionKey, newAccessToken)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt access token: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     p.accessTokenCookieName,
		Value:    encryptedAccessToken,
		Path:     "/",
		MaxAge:   p.session.AccessTTLSeconds(),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: p.session.SameSite,
	})

	// Encrypt and set refresh token cookie
	encryptedRefreshToken, err := encryption.EncryptCookie(p.encryptionKey, newRefreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     p.refreshTokenCookieName,
		Value:    encryptedRefreshToken,
		Path:     "/",
		MaxAge:   p.session.RefreshTTLSeconds(),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: p.session.SameSite,
	})

	return newAccessToken, nil
}

// reauthorizeStoredGrant re-derives the identity from the stored grant props and
// runs it through the allowlist. It returns nil if allowed. It fails closed:
//   - a nil authorizer returns authz.ErrDenied (deny, never allow) — CONCERN 1.
//   - an actual allowlist deny returns authz.ErrDenied.
//   - an infrastructure failure (grant load/decrypt) returns a non-nil error
//     that is NOT authz.ErrDenied, so the caller denies the request without
//     destroying the session — CONCERN 2.
func (p *TokenValidator) reauthorizeStoredGrant(grantID, userID string) error {
	if p.authorizer == nil {
		return authz.ErrDenied
	}

	grant, err := p.db.GetGrant(grantID, userID)
	if err != nil {
		return fmt.Errorf("failed to load grant for re-authorization: %w", err)
	}
	// Defensive: production GetGrant errors on not-found (never returns nil,nil),
	// but the interface permits it. A nil grant is an infrastructure condition,
	// NOT an authorization deny, so return a non-ErrDenied error to avoid both a
	// panic and revoking the session (CONCERN 2).
	if grant == nil {
		return fmt.Errorf("grant not found for re-authorization")
	}

	props := grant.Props
	if props != nil {
		decrypted, derr := encryption.DecryptPropsIfNeeded(p.encryptionKey, props)
		if derr != nil {
			return fmt.Errorf("failed to decrypt grant props for re-authorization: %w", derr)
		}
		props = decrypted
	}

	return authz.AuthorizeStoredProps(p.authorizer, props)
}

// revokeGrantTokens revokes the WHOLE session for a grant whose authorization
// was revoked on refresh, forcing the client to re-authenticate. It revokes all
// tokens for the grant (BLOCKER 2) and, defensively, the specific refresh/access
// token pair too.
func (p *TokenValidator) revokeGrantTokens(refreshToken string, tokenData *types.TokenData) {
	if tokenData != nil && tokenData.GrantID != "" {
		if err := p.db.RevokeTokensByGrant(tokenData.GrantID); err != nil {
			fmt.Printf("Failed to revoke session by grant after authorization deny: %v\n", err)
		}
	}
	if err := p.db.RevokeToken(refreshToken); err != nil {
		fmt.Printf("Failed to revoke refresh token after authorization deny: %v\n", err)
	}
	if tokenData != nil && tokenData.AccessToken != "" {
		if err := p.db.RevokeToken(tokenData.AccessToken); err != nil {
			fmt.Printf("Failed to revoke access token after authorization deny: %v\n", err)
		}
	}
}

func (p *TokenValidator) handleOauthFlow(w http.ResponseWriter, r *http.Request) {
	// Check if OAuth provider is configured
	if p.provider == nil || p.clientID == "" || p.clientSecret == "" {
		handlerutils.JSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "OAuth provider not configured",
		})
		return
	}

	// Generate PKCE parameters
	codeVerifier, codeChallenge := generatePKCE()

	// Generate a random state key for this auth request
	stateKey := encryption.GenerateRandomString(32)

	// Get current path for post-auth redirect
	currentPath := r.URL.Path
	if r.URL.RawQuery != "" {
		currentPath += "?" + r.URL.RawQuery
	}

	// Store the auth request data in the database with PKCE parameters
	authData := map[string]any{
		"response_type":         "code",
		"client_id":             p.clientID,
		"redirect_uri":          fmt.Sprintf("%s/callback", handlerutils.GetBaseURL(r)),
		"scope":                 strings.Join(p.scopesSupported, " "),
		"state":                 stateKey,
		"code_challenge":        codeChallenge,
		"code_challenge_method": "S256",
		"code_verifier":         codeVerifier, // Store for later use in token exchange
		"rd":                    currentPath,  // Store original path for post-auth redirect
	}

	if err := p.db.StoreAuthRequest(stateKey, authData); err != nil {
		handlerutils.JSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to store authorization request",
		})
		return
	}

	// Build the authorization URL directly to OAuth provider (not our /authorize)
	redirectURI := fmt.Sprintf("%s%s/callback", handlerutils.GetBaseURL(r), p.routePrefix)
	scope := strings.Join(p.scopesSupported, " ")

	// Generate authorization URL with PKCE
	authURL := p.provider.GetAuthorizationURL(p.clientID, redirectURI, scope, stateKey)

	w.Header().Set("X-Redirect-URL", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (p *TokenValidator) sendUnauthorizedResponse(w http.ResponseWriter, r *http.Request, message string) {
	if !slices.Contains(p.mcpPaths, r.URL.Path) && strings.Contains(strings.ToLower(r.UserAgent()), "mozilla") {
		p.handleOauthFlow(w, r)
		return
	}

	// Agent / non-browser path: emit the shared 401 re-auth challenge so the
	// client can re-run discovery / PKCE. Shared with the proxy in-request
	// expiry/deny paths so all agent challenges are byte-for-byte identical.
	handlerutils.WriteBearerChallenge(w, r, message)
}

func GetTokenInfo(r *http.Request) *tokens.TokenInfo {
	v, _ := r.Context().Value(tokenInfoKey{}).(*tokens.TokenInfo)
	return v
}

// GetBearerToken returns the inbound bearer/cookie token string stored on the
// request context by WithTokenValidation, or "" if none.
func GetBearerToken(r *http.Request) string {
	v, _ := r.Context().Value(bearerTokenKey{}).(string)
	return v
}

type tokenInfoKey struct{}
type bearerTokenKey struct{}

// ContextWithTokenInfo stages a validated token info on the context under the
// same key WithTokenValidation uses. It exists ONLY to let tests in other
// packages drive handlers that read GetTokenInfo without standing up the full
// validation middleware. Do not call it from production code.
func ContextWithTokenInfo(ctx context.Context, ti *tokens.TokenInfo) context.Context {
	return context.WithValue(ctx, tokenInfoKey{}, ti)
}
