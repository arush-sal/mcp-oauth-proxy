package authorize

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

type AuthorizationStore interface {
	GetClient(clientID string) (*types.ClientInfo, error)
	StoreAuthRequest(key string, data map[string]any) error
}

type Handler struct {
	db              AuthorizationStore
	provider        providers.Provider
	scopesSupported []string
	clientID        string
	clientSecret    string
	routePrefix     string
}

func NewHandler(db AuthorizationStore, provider providers.Provider, scopesSupported []string, clientID, clientSecret, routePrefix string) http.Handler {
	return &Handler{
		db:              db,
		provider:        provider,
		scopesSupported: scopesSupported,
		clientID:        clientID,
		clientSecret:    clientSecret,
		routePrefix:     routePrefix,
	}
}

// isPublicClient reports whether a client lacks a usable secret and is therefore
// a "public" client for PKCE purposes: it either declared
// token_endpoint_auth_method == "none" or has no stored client secret.
func isPublicClient(c *types.ClientInfo) bool {
	return c.TokenEndpointAuthMethod == "none" || c.ClientSecret == ""
}

func (p *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get parameters from query or form
	var params url.Values
	if r.Method == "GET" {
		params = r.URL.Query()
	} else {
		if err := r.ParseForm(); err != nil {
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_request",
				ErrorDescription: "Failed to parse form data",
			})
			return
		}
		params = r.Form
	}

	// Parse authorization request
	authReq := types.AuthRequest{
		ResponseType:        params.Get("response_type"),
		ClientID:            params.Get("client_id"),
		RedirectURI:         params.Get("redirect_uri"),
		Scope:               params.Get("scope"),
		State:               params.Get("state"),
		CodeChallenge:       params.Get("code_challenge"),
		CodeChallengeMethod: params.Get("code_challenge_method"),
	}

	if authReq.Scope == "" {
		authReq.Scope = strings.Join(p.scopesSupported, " ")
	}

	// Validate required parameters
	if authReq.ResponseType == "" || authReq.ClientID == "" || authReq.RedirectURI == "" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Missing required parameters",
		})
		return
	}

	// Validate response type
	if authReq.ResponseType != "code" && authReq.ResponseType != "token" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "unsupported_response_type",
			ErrorDescription: "Only 'code' and 'token' response types are supported",
		})
		return
	}

	// Validate client exists
	clientInfo, err := p.db.GetClient(authReq.ClientID)
	if err != nil || clientInfo == nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_client",
			ErrorDescription: "Client not found",
		})
		return
	}

	if !slices.Contains(clientInfo.RedirectUris, authReq.RedirectURI) {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid redirect URI",
		})
		return
	}

	// H1 (Fix 2): public clients (no usable secret) must use PKCE with S256.
	// Without a client secret, a stolen authorization code is otherwise directly
	// redeemable, so requiring a code_challenge bound to the request is the only
	// protection against auth-code interception. We reject a missing challenge
	// and the downgradeable "plain" method here, before any state is stored.
	// Confidential clients (with a secret) keep their prior behavior.
	if isPublicClient(clientInfo) {
		if authReq.CodeChallenge == "" {
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_request",
				ErrorDescription: "code_challenge is required for public clients (PKCE S256)",
			})
			return
		}
		if authReq.CodeChallengeMethod != "S256" {
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_request",
				ErrorDescription: "code_challenge_method must be S256 for public clients",
			})
			return
		}
	}

	// Check if provider is configured
	if p.clientID == "" || p.clientSecret == "" {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "OAuth provider not configured",
		})
		return
	}

	// Generate a random state key
	stateKey := encryption.GenerateRandomString(32)

	// Store the auth request data in the database
	authData := map[string]any{
		"response_type":         authReq.ResponseType,
		"client_id":             authReq.ClientID,
		"redirect_uri":          authReq.RedirectURI,
		"scope":                 authReq.Scope,
		"state":                 authReq.State,
		"code_challenge":        authReq.CodeChallenge,
		"code_challenge_method": authReq.CodeChallengeMethod,
	}

	// Add redirect parameter if present for post-auth redirect
	if rd := params.Get("rd"); rd != "" {
		authData["rd"] = rd
	}

	if err := p.db.StoreAuthRequest(stateKey, authData); err != nil {
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to store authorization request",
		})
		return
	}

	redirectURI := fmt.Sprintf("%s%s/callback", handlerutils.GetBaseURL(r), p.routePrefix)
	http.SetCookie(w, &http.Cookie{
		Name:     types.OAuthStateCookieName,
		Value:    stateKey,
		Path:     p.routePrefix + "/callback",
		MaxAge:   15 * 60,
		HttpOnly: true,
		Secure:   handlerutils.RequestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	// Generate authorization URL with the provider
	authURL := p.provider.GetAuthorizationURL(
		p.clientID,
		redirectURI,
		authReq.Scope,
		stateKey,
	)

	// Redirect to the provider's authorization URL
	http.Redirect(w, r, authURL, http.StatusFound)
}
