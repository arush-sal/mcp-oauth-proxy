package token

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/authz"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

type TokenStore interface {
	GetClient(clientID string) (*types.ClientInfo, error)
	StoreToken(token *types.TokenData) error
	ValidateAuthCode(code string) (string, string, error)
	GetGrant(grantID string, userID string) (*types.Grant, error)
	DeleteAuthCode(code string) error
	GetTokenByRefreshToken(refreshToken string) (*types.TokenData, error)
	RevokeToken(token string) error
	RevokeTokensByGrant(grantID string) error
}

type Handler struct {
	db TokenStore
	// authorizer enforces the allowlist; it is re-checked on the refresh_token
	// grant so agents using standard OAuth2 refresh are re-evaluated on every
	// refresh. A nil authorizer fails closed (deny).
	authorizer *authz.Authorizer
	// encryptionKey decrypts grant props for the refresh-time re-authorization.
	encryptionKey []byte
}

func NewHandler(db TokenStore, authorizer *authz.Authorizer, encryptionKey []byte) http.Handler {
	return &Handler{
		db:            db,
		authorizer:    authorizer,
		encryptionKey: encryptionKey,
	}
}

func (p *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body",
		})
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Check for client ID
	if clientID == "" {
		handlerutils.JSON(w, http.StatusUnauthorized, types.OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client ID is required",
		})
		return
	}

	// Get client info to determine authentication method
	clientInfo, err := p.db.GetClient(clientID)
	if err != nil || clientInfo == nil {
		handlerutils.JSON(w, http.StatusUnauthorized, types.OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client not found",
		})
		return
	}

	// Check if this is a public client (auth method "none")
	isPublicClient := clientInfo.TokenEndpointAuthMethod == "none"

	// For public clients, client_secret is not required
	// For confidential clients, client_secret is required
	if !isPublicClient {
		if clientSecret == "" {
			handlerutils.JSON(w, http.StatusUnauthorized, types.OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Client secret is required for confidential clients",
			})
			return
		}

		// Validate client secret for confidential clients
		if clientInfo.ClientSecret != clientSecret {
			handlerutils.JSON(w, http.StatusUnauthorized, types.OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Invalid client secret",
			})
			return
		}
	}

	switch grantType {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r, clientID)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r, clientID)
	default:
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "unsupported_grant_type",
			ErrorDescription: "The grant type is not supported by this authorization server",
		})
	}
}

func (p *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, clientID string) {
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")

	// Validate authorization code
	grantID, userID, err := p.db.ValidateAuthCode(code)
	if err != nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Invalid authorization code",
		})
		return
	}

	// Get the grant
	grant, err := p.db.GetGrant(grantID, userID)
	if err != nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Grant not found",
		})
		return
	}

	// Verify client ID matches
	if grant.ClientID != clientID {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Client ID mismatch",
		})
		return
	}

	// Validate redirect_uri if provided
	if redirectURI != "" {
		// Get client info to validate redirect URI
		clientInfo, err := p.db.GetClient(clientID)
		if err != nil || clientInfo == nil {
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_client",
				ErrorDescription: "Client not found",
			})
			return
		}

		// Check if redirect URI is registered for this client
		if !slices.Contains(clientInfo.RedirectUris, redirectURI) {
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_grant",
				ErrorDescription: "Invalid redirect URI",
			})
			return
		}
	}

	// Check if PKCE is being used
	isPkceEnabled := grant.CodeChallenge != ""

	// OAuth 2.1 requires redirect_uri parameter unless PKCE is used
	if redirectURI == "" && !isPkceEnabled {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "redirect_uri is required when not using PKCE",
		})
		return
	}

	// Check PKCE if code_verifier is provided
	if codeVerifier != "" {
		if !isPkceEnabled {
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_request",
				ErrorDescription: "code_verifier provided for a flow that did not use PKCE",
			})
			return
		}

		// Verify PKCE code_verifier
		calculatedChallenge := ""
		if grant.CodeChallengeMethod == "S256" {
			hash := sha256.Sum256([]byte(codeVerifier))
			calculatedChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
		} else {
			calculatedChallenge = codeVerifier
		}

		if calculatedChallenge != grant.CodeChallenge {
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_grant",
				ErrorDescription: "Invalid PKCE code_verifier",
			})
			return
		}
	}

	// Props are stored in the grant and will be accessed when needed
	// For simple string token generation, we don't need to decrypt them here

	// Generate access token in format: userId:grantId:accessTokenSecret
	accessTokenSecret := encryption.GenerateRandomString(32)
	accessToken := fmt.Sprintf("%s:%s:%s", userID, grantID, accessTokenSecret)

	// Generate refresh token in format: userId:grantId:refreshTokenSecret
	refreshTokenSecret := encryption.GenerateRandomString(32)
	refreshToken := fmt.Sprintf("%s:%s:%s", userID, grantID, refreshTokenSecret)

	// Store tokens in database
	tokenData := &types.TokenData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     clientID,
		UserID:       userID,
		GrantID:      grantID,
		Scope:        strings.Join(grant.Scope, " "),
		ExpiresAt:    time.Now().Add(time.Duration(3600) * time.Second),
		CreatedAt:    time.Now(),
	}

	if err := p.db.StoreToken(tokenData); err != nil {
		log.Printf("Failed to store token: %v", err)
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store token",
		})
		return
	}

	// Delete the authorization code (single-use)
	if err := p.db.DeleteAuthCode(code); err != nil {
		log.Printf("Error deleting authorization code: %v", err)
	}

	response := types.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        strings.Join(grant.Scope, " "),
	}

	handlerutils.JSON(w, http.StatusOK, response)
}

// reauthorizeGrant re-derives the identity from the grant's stored (decrypted)
// props and re-runs the allowlist. It fails closed: a nil authorizer returns
// authz.ErrDenied. A props-decrypt failure returns a non-ErrDenied error so the
// caller treats it as an infrastructure error (deny this request, keep the
// session) rather than an authorization deny (CONCERN 2).
func (p *Handler) reauthorizeGrant(grant *types.Grant) error {
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

func (p *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, clientID string) {
	// Capture the inbound (old) refresh token up front. It is the token to
	// revoke after rotation; the local refreshToken variable is later reused for
	// the newly generated token (BLOCKER 4).
	oldRefreshToken := r.FormValue("refresh_token")
	refreshToken := oldRefreshToken

	// Validate refresh token from database
	tokenData, err := p.db.GetTokenByRefreshToken(refreshToken)
	if err != nil {
		handlerutils.JSON(w, http.StatusUnauthorized, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Invalid refresh token",
		})
		return
	}

	// Check if token is revoked
	if tokenData.Revoked {
		handlerutils.JSON(w, http.StatusUnauthorized, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Token has been revoked",
		})
		return
	}

	// Check if refresh token is expired
	if time.Now().After(tokenData.RefreshTokenExpiresAt) {
		handlerutils.JSON(w, http.StatusUnauthorized, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Refresh token has expired",
		})
		return
	}

	// Check if token belongs to the requesting client
	if tokenData.ClientID != clientID {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Token does not belong to the requesting client",
		})
		return
	}

	// Get the grant to access props
	grant, err := p.db.GetGrant(tokenData.GrantID, tokenData.UserID)
	if err != nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Grant not found",
		})
		return
	}

	// Re-check the allowlist on every refresh_token grant (BLOCKER 3). This is
	// the standard OAuth2 POST /token path used by agents; without this re-check
	// it would be a full bypass of "re-check on every refresh". This path does
	// NOT contact the IdP, so the identity is re-derived from the STORED grant
	// claims (same approach as the internal validate refresh). On an actual
	// authorization DENY we revoke the WHOLE session and refuse to issue tokens.
	// On an infrastructure error (props decrypt failure) we fail closed for THIS
	// request but keep the session (CONCERN 2).
	if err := p.reauthorizeGrant(grant); err != nil {
		if errors.Is(err, authz.ErrDenied) {
			log.Printf("authorization revoked on refresh_token grant for grant=%q: %v", tokenData.GrantID, err)
			if rerr := p.db.RevokeTokensByGrant(tokenData.GrantID); rerr != nil {
				log.Printf("Failed to revoke session by grant after authorization deny: %v", rerr)
			}
			handlerutils.JSON(w, http.StatusForbidden, types.OAuthError{
				Error:            "access_denied",
				ErrorDescription: "Access denied: you are no longer authorized to use this resource",
			})
			return
		}
		// Infrastructure error: deny this request, preserve the session.
		log.Printf("authorization re-check failed on refresh_token grant for grant=%q (session preserved): %v", tokenData.GrantID, err)
		handlerutils.JSON(w, http.StatusUnauthorized, types.OAuthError{
			Error:            "invalid_grant",
			ErrorDescription: "Authorization re-check failed",
		})
		return
	}

	// Generate new access token in format: userId:grantId:accessTokenSecret
	accessTokenSecret := encryption.GenerateRandomString(32)
	accessToken := fmt.Sprintf("%s:%s:%s", tokenData.UserID, tokenData.GrantID, accessTokenSecret)

	// Generate new refresh token
	refreshTokenSecret := encryption.GenerateRandomString(32)
	refreshToken = fmt.Sprintf("%s:%s:%s", tokenData.UserID, tokenData.GrantID, refreshTokenSecret)
	refreshTokenExpiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days from now

	// Store new token in database (replaces the old one)
	newTokenData := &types.TokenData{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		ClientID:              clientID,
		UserID:                tokenData.UserID,
		GrantID:               tokenData.GrantID,
		Scope:                 tokenData.Scope,
		ExpiresAt:             time.Now().Add(3600 * time.Second),
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		CreatedAt:             time.Now(),
	}

	if err := p.db.StoreToken(newTokenData); err != nil {
		log.Printf("Failed to store new token: %v", err)
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store new token",
		})
		return
	}

	// Revoke the OLD (inbound) refresh token, not the freshly minted one
	// (BLOCKER 4). At this point `refreshToken` has been reassigned to the new
	// token, so we must revoke the captured oldRefreshToken to make the previous
	// token unusable and complete the rotation.
	if err := p.db.RevokeToken(oldRefreshToken); err != nil {
		log.Printf("Failed to revoke old refresh token: %v", err)
	}

	response := types.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        tokenData.Scope,
	}

	handlerutils.JSON(w, http.StatusOK, response)
}
