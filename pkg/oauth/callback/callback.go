package callback

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/authz"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

type Store interface {
	StoreGrant(grant *types.Grant) error
	StoreAuthCode(code, grantID, userID string) error
	GetAuthRequest(key string) (map[string]any, error)
	DeleteAuthRequest(key string) error
	StoreToken(token *types.TokenData) error
}

// IDTokenVerifier verifies an IdP-issued OIDC id_token and returns its
// normalized claims. *idtoken.Verifier satisfies this interface. It is kept as
// an interface so the verifier is optional (a nil verifier disables id_token
// verification) and so the handler can be tested in isolation.
type IDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*idtoken.Claims, error)
}

type Handler struct {
	db               Store
	provider         providers.Provider
	encryptionKey    []byte
	clientID         string
	clientSecret     string
	routePrefix      string
	cookieNamePrefix string
	// idTokenVerifier is optional. When nil, the IdP id_token (if any) is not
	// verified and no id_token claims are stored, which is the behavior-neutral
	// default for non-OIDC setups.
	idTokenVerifier IDTokenVerifier
	// authorizer enforces the allowlist (who may use the proxy). It is always
	// non-nil; a zero-config authorizer denies everyone (fail-closed default).
	authorizer *authz.Authorizer
	// session carries the resolved cookie/session lifetime and security policy.
	session types.SessionConfig
}

// MCPUIManager interface for generating JWT tokens
type MCPUIManager interface {
	GenerateMCPUICodeForDownstream(bearerToken, refreshToken string) (string, error)
}

func NewHandler(db Store, provider providers.Provider, encryptionKey []byte, clientID, clientSecret, routePrefix, cookieNamePrefix string, idTokenVerifier IDTokenVerifier, authorizer *authz.Authorizer, session types.SessionConfig) http.Handler {
	return &Handler{
		db:               db,
		provider:         provider,
		encryptionKey:    encryptionKey,
		clientID:         clientID,
		clientSecret:     clientSecret,
		routePrefix:      routePrefix,
		cookieNamePrefix: cookieNamePrefix,
		idTokenVerifier:  idTokenVerifier,
		authorizer:       authorizer,
		session:          session,
	}
}

// idTokenExtractor is satisfied by *oauth2.Token; it exposes the raw id_token
// stored in the token's extra fields by the OIDC token endpoint.
type idTokenExtractor interface {
	Extra(key string) any
}

// verifyIDToken pulls the raw id_token out of the token-exchange result and, if
// present and a verifier is configured, verifies it and returns the normalized
// claims plus the raw token. Behavior:
//   - no verifier configured (non-OIDC setup): returns (nil, "", nil)
//   - no id_token present: returns (nil, "", nil)
//   - id_token present but invalid: returns (nil, "", err) -> caller rejects
//   - id_token present and valid: returns (claims, rawIDToken, nil)
func (p *Handler) verifyIDToken(ctx context.Context, tok idTokenExtractor) (*idtoken.Claims, string, error) {
	if p.idTokenVerifier == nil || tok == nil {
		return nil, "", nil
	}

	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, "", nil
	}

	claims, err := p.idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", err
	}
	return claims, rawIDToken, nil
}

// scopeContainsProfileOrEmail checks if the given scopes contain profile or email
func (p *Handler) scopeContainsProfileOrEmail(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "profile" || scope == "email" {
			return true
		}
	}
	return false
}

// getStringFromMap safely extracts a string value from a map[string]any
func getStringFromMap(data map[string]any, key string) string {
	if value, ok := data[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// setEncryptedCookie sets an encrypted cookie with security attributes
func (p *Handler) setEncryptedCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) error {
	encryptedValue, err := encryption.EncryptCookie(p.encryptionKey, value)
	if err != nil {
		return fmt.Errorf("failed to encrypt cookie: %w", err)
	}

	cookie := &http.Cookie{
		Name:     name,
		Value:    encryptedValue,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   p.session.SecureForRequest(handlerutils.RequestIsHTTPS(r)),
		SameSite: p.session.SameSite,
	}

	http.SetCookie(w, cookie)
	return nil
}

// isValidRelativePath validates that a redirect path is relative and safe
func isValidRelativePath(path string) bool {
	// Must start with / and not be a protocol-relative URL
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return false
	}
	// No backslashes (Windows path confusion)
	if strings.Contains(path, "\\") {
		return false
	}
	return true
}

func (p *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle OAuth callback from external providers
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	error := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	stateCookie, err := r.Cookie(types.OAuthStateCookieName)
	if err != nil || state == "" || stateCookie.Value != state {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid or missing state cookie",
		})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     types.OAuthStateCookieName,
		Value:    "",
		Path:     p.routePrefix + "/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   p.session.SecureForRequest(handlerutils.RequestIsHTTPS(r)),
		SameSite: p.session.SameSite,
	})

	// Check for OAuth errors
	if error != "" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            error,
			ErrorDescription: errorDescription,
		})
		return
	}

	// Validate required parameters
	if code == "" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Missing authorization code",
		})
		return
	}

	// Retrieve auth request data from database using state as key
	authData, err := p.db.GetAuthRequest(state)
	if err != nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid or expired state parameter",
		})
		return
	}

	// Convert auth data back to AuthRequest struct
	authReq := types.AuthRequest{
		ResponseType:        getStringFromMap(authData, "response_type"),
		ClientID:            getStringFromMap(authData, "client_id"),
		RedirectURI:         getStringFromMap(authData, "redirect_uri"),
		Scope:               getStringFromMap(authData, "scope"),
		State:               getStringFromMap(authData, "state"),
		CodeChallenge:       getStringFromMap(authData, "code_challenge"),
		CodeChallengeMethod: getStringFromMap(authData, "code_challenge_method"),
	}

	// Clean up the auth request data after successful retrieval
	defer func() {
		if err := p.db.DeleteAuthRequest(state); err != nil {
			log.Printf("Failed to delete auth request: %v", err)
		}
	}()

	// Get provider credentials
	redirectURI := fmt.Sprintf("%s%s/callback", handlerutils.GetBaseURL(r), p.routePrefix)

	// Exchange code for tokens
	tokenInfo, err := p.provider.ExchangeCodeForToken(r.Context(), code, p.clientID, p.clientSecret, redirectURI)
	if err != nil {
		log.Printf("Failed to exchange code for token: %v", err)
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Failed to exchange authorization code",
		})
		return
	}

	// If the IdP returned an OIDC id_token and an id_token verifier is
	// configured, verify it and capture normalized claims. Authorization is made
	// claims-first off these verified claims. If no id_token is present we
	// proceed with empty claims and rely on the userinfo fallback. If
	// verification FAILS, we reject the login rather than silently proceeding
	// with an unverified token.
	idTokenClaims, rawIDToken, err := p.verifyIDToken(r.Context(), tokenInfo)
	if err != nil {
		log.Printf("Failed to verify id_token: %v", err)
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Failed to verify identity token",
		})
		return
	}

	// Check if scope includes profile or email before getting user info. We also
	// fetch userinfo when the authorizer needs an attribute (email) that the
	// id_token did not supply, so authorization can fall back to userinfo.
	scopes := strings.Fields(authReq.Scope)
	needsUserInfo := p.scopeContainsProfileOrEmail(scopes)
	if p.authorizer != nil && p.authorizer.NeedsEmail() &&
		(idTokenClaims == nil || idTokenClaims.Email == "") {
		needsUserInfo = true
	}

	userInfo := &providers.UserInfo{}
	if needsUserInfo {
		// Get user info from the provider
		userInfo, err = p.provider.GetUserInfo(r.Context(), tokenInfo.AccessToken)
		if err != nil {
			log.Printf("Failed to get user info: %v", err)
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_grant",
				ErrorDescription: "Failed to get user information",
			})
			return
		}
	}

	// Enforce the allowlist (WHO may use the proxy) against the verified id_token
	// claims first, falling back to userinfo for attributes a rule needs but the
	// id_token lacked. A zero-config authorizer denies everyone (fail-closed
	// default). On deny we return 403 access_denied and store nothing.
	identity := authz.IdentityFromClaims(idTokenClaims)
	identity = authz.MergeUserInfo(identity, userInfo.Email, userInfo.EmailVerified)
	if p.authorizer == nil {
		// Defensive: a nil authorizer would mean "no allowlist", which violates
		// the fail-closed contract. Deny.
		log.Printf("authorization denied: no authorizer configured")
		handlerutils.JSON(w, http.StatusForbidden, types.OAuthError{
			Error:            "access_denied",
			ErrorDescription: "Access denied",
		})
		return
	}
	if err := p.authorizer.Authorize(identity); err != nil {
		log.Printf("authorization denied for subject=%q: %v", identity.Subject, err)
		handlerutils.JSON(w, http.StatusForbidden, types.OAuthError{
			Error:            "access_denied",
			ErrorDescription: "Access denied: you are not authorized to use this resource",
		})
		return
	}

	// Create a grant for this user
	grantID := encryption.GenerateRandomString(16)
	now := time.Now().Unix()

	// Prepare sensitive props data
	sensitiveProps := map[string]any{
		"access_token":  tokenInfo.AccessToken,
		"refresh_token": tokenInfo.RefreshToken,
		"expires_at":    tokenInfo.Expiry.Unix(),
	}

	// Store verified id_token claims (and the raw token) so a later feature can
	// authorize on them. Only present when an id_token was returned and a
	// verifier is configured.
	if idTokenClaims != nil {
		claimsJSON, marshalErr := json.Marshal(idTokenClaims)
		if marshalErr != nil {
			log.Printf("Failed to marshal id_token claims: %v", marshalErr)
			handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
				Error:            "server_error",
				ErrorDescription: "Failed to process identity token",
			})
			return
		}
		sensitiveProps["id_token_claims"] = string(claimsJSON)
		sensitiveProps["id_token"] = rawIDToken
		// Store the id_token's OWN exp (Unix seconds) so the forwarding staleness
		// check can avoid re-parsing the raw JWT per request. This is the id_token
		// exp, DISTINCT from sensitiveProps["expires_at"] (the IdP access-token
		// expiry, tokenInfo.Expiry).
		sensitiveProps["id_token_exp"] = idTokenClaims.ExpiresAt
	}

	// Only add user info if we have it
	if needsUserInfo {
		sensitiveProps["email"] = userInfo.Email
		sensitiveProps["name"] = userInfo.Name
		infoJSON, _ := json.Marshal(userInfo)
		sensitiveProps["info"] = string(infoJSON)

		// Keep the top-level email/email_verified pair SELF-CONSISTENT: the stored
		// email is the userinfo email, so its verified flag MUST be the userinfo
		// email's verified state. Borrowing the id_token's EmailVerified here would
		// describe a DIFFERENT email and could promote an unverified userinfo
		// address to verified on a later refresh re-check. The id_token's own
		// email+verified live in id_token_claims and remain preferred by
		// IdentityFromStoredProps.
		sensitiveProps["email_verified"] = userInfo.EmailVerified
	}

	// Initialize props map
	props := make(map[string]any)

	// Encrypt the sensitive props data
	encryptedProps, err := encryption.EncryptData(sensitiveProps, p.encryptionKey)
	if err != nil {
		log.Printf("Failed to encrypt props data: %v", err)
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to encrypt sensitive data",
		})
		return
	}

	// Store encrypted data
	props["encrypted_data"] = encryptedProps.Data
	props["iv"] = encryptedProps.IV
	props["algorithm"] = encryptedProps.Algorithm
	props["encrypted"] = true

	grant := &types.Grant{
		ID:       grantID,
		ClientID: authReq.ClientID,
		UserID:   userInfo.ID,
		Scope:    scopes,
		Metadata: map[string]any{
			"provider": p.provider,
		},
		Props:               props,
		CreatedAt:           now,
		ExpiresAt:           now + int64(p.session.RefreshTTL.Seconds()), // grant expiry mirrors the refresh token lifetime
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
	}

	// Store the grant
	if err := p.db.StoreGrant(grant); err != nil {
		log.Printf("Failed to store grant: %v", err)
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store grant",
		})
		return
	}

	// Generate authorization code
	randomPart := encryption.GenerateRandomString(32)
	authCode := fmt.Sprintf("%s:%s:%s", userInfo.ID, grantID, randomPart)

	// Store the authorization code
	if err := p.db.StoreAuthCode(authCode, grantID, userInfo.ID); err != nil {
		log.Printf("Failed to store authorization code: %v", err)
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store authorization code",
		})
		return
	}

	if rdValue := getStringFromMap(authData, "rd"); rdValue != "" {
		// Validate redirect path for security
		if !isValidRelativePath(rdValue) {
			log.Printf("Invalid redirect path: %s", rdValue)
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_request",
				ErrorDescription: "Invalid redirect path",
			})
			return
		}

		// This is a UI flow - generate internal tokens and set session cookies
		// Generate internal application tokens (separate from OAuth provider tokens)
		accessTokenSecret := encryption.GenerateRandomString(32)
		accessToken := fmt.Sprintf("%s:%s:%s", userInfo.ID, grantID, accessTokenSecret)

		refreshTokenSecret := encryption.GenerateRandomString(32)
		refreshToken := fmt.Sprintf("%s:%s:%s", userInfo.ID, grantID, refreshTokenSecret)

		// Store internal tokens in database
		tokenData := &types.TokenData{
			AccessToken:           accessToken,
			RefreshToken:          refreshToken,
			ClientID:              authReq.ClientID,
			UserID:                userInfo.ID,
			GrantID:               grantID,
			Scope:                 authReq.Scope,
			ExpiresAt:             time.Now().Add(p.session.AccessTTL),  // access token lifetime
			RefreshTokenExpiresAt: time.Now().Add(p.session.RefreshTTL), // refresh token lifetime
			CreatedAt:             time.Now(),
			Revoked:               false,
		}

		if err := p.db.StoreToken(tokenData); err != nil {
			handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
				Error:            "server_error",
				ErrorDescription: "Failed to store tokens",
			})
			return
		}

		// Set encrypted cookies
		accessCookieName := p.cookieNamePrefix + types.AccessTokenCookieName
		refreshCookieName := p.cookieNamePrefix + types.RefreshTokenCookieName

		// Access token cookie
		if err := p.setEncryptedCookie(w, r, accessCookieName, accessToken, p.session.AccessTTLSeconds()); err != nil {
			log.Printf("Failed to set access token cookie: %v", err)
			handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
				Error:            "server_error",
				ErrorDescription: "Failed to set authentication cookies",
			})
			return
		}

		// Refresh token cookie
		if err := p.setEncryptedCookie(w, r, refreshCookieName, refreshToken, p.session.RefreshTTLSeconds()); err != nil {
			log.Printf("Failed to set refresh token cookie: %v", err)
			handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
				Error:            "server_error",
				ErrorDescription: "Failed to set authentication cookies",
			})
			return
		}

		// Redirect to original URL (rdValue is already a relative path)
		redirectURL := handlerutils.GetBaseURL(r) + rdValue
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Build the redirect URL back to the client
	redirectURL := authReq.RedirectURI

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Invalid redirect URL",
		})
		return
	}

	query := parsedURL.Query()
	query.Set("code", authCode)
	if authReq.State != "" {
		query.Set("state", authReq.State)
	}
	parsedURL.RawQuery = query.Encode()

	// Redirect back to the client
	http.Redirect(w, r, parsedURL.String(), http.StatusFound)
}
