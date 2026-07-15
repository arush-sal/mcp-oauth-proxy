package register

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

// validateRedirectURI enforces the DCR redirect URI allowlist (RFC 7591
// invalid_redirect_uri). Accepted:
//   - https with a host (any host);
//   - loopback http (127.0.0.1 / localhost / [::1], optional port/path);
//   - a private-use URI scheme (RFC 8252 §7.1) for native apps, e.g.
//     "cursor://anysphere.cursor-mcp/oauth/callback" or "com.example.app:/cb".
//
// For every URI a fragment, embedded credentials (user:pass@) and a wildcard
// ("*") are rejected. Non-loopback http is rejected. Private-use schemes must be
// syntactically valid (RFC 3986) and are denied when they name a known
// dangerous / non-app scheme (javascript, data, file, ...). A custom-scheme
// redirect can only be delivered to an app registered for that scheme on the
// user's own device, so unlike an attacker-controlled https host it is not a
// remote code-interception vector; the identity allowlist + PKCE remain the
// primary gate.
func validateRedirectURI(raw string) error {
	if raw == "" {
		return fmt.Errorf("redirect URI must not be empty")
	}
	// Wildcards are never allowed (open-redirect / pattern matching abuse).
	if strings.Contains(raw, "*") {
		return fmt.Errorf("redirect URI %q must not contain a wildcard", raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect URI %q is not a valid URL", raw)
	}

	// Fragments are not permitted on redirect URIs (RFC 6749 §3.1.2).
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("redirect URI %q must not contain a fragment", raw)
	}

	// Embedded credentials (user:pass@host) are forbidden.
	if u.User != nil {
		return fmt.Errorf("redirect URI %q must not contain embedded credentials", raw)
	}

	// Classify by scheme (case-insensitive per RFC 3986). Never rewrite the raw
	// value: /authorize and /token compare redirect_uri by exact string, so any
	// normalization must stay confined to this validation.
	switch strings.ToLower(u.Scheme) {
	case "https":
		// https must carry a host; "https:///path" is not a valid target.
		if u.Hostname() == "" {
			return fmt.Errorf("redirect URI %q must have a host", raw)
		}
		return nil
	case "http":
		if u.Hostname() == "" {
			return fmt.Errorf("redirect URI %q must have a host", raw)
		}
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("redirect URI %q uses http with a non-loopback host; only https, loopback http, or a private-use URI scheme is allowed", raw)
	default:
		// Private-use URI scheme (RFC 8252 §7.1). Authority is optional: both
		// "scheme://host/path" and "scheme:/path" are legitimate native-app forms,
		// so we do NOT require a host here.
		return validatePrivateUseScheme(u.Scheme, raw)
	}
}

// deniedRedirectSchemes lists schemes that are never valid native-app redirect
// targets and are dangerous if a redirect value is ever dereferenced in a
// browser-like context (code execution, local file / inline data access) or are
// simply not app-callback schemes.
var deniedRedirectSchemes = map[string]bool{
	"javascript": true,
	"data":       true,
	"vbscript":   true,
	"file":       true,
	"blob":       true,
	"about":      true,
	"mailto":     true,
	"tel":        true,
	"urn":        true,
	"ws":         true,
	"wss":        true,
}

// validatePrivateUseScheme accepts an RFC 8252 §7.1 private-use URI scheme. The
// scheme must be syntactically valid per RFC 3986 and bounded in length, and
// must not be a known dangerous / non-app scheme. Per RFC 8252 a reverse-DNS
// scheme ("com.example.app") is RECOMMENDED but NOT required, so single-label
// schemes such as "cursor" are deliberately allowed - requiring a dot would
// break real clients (e.g. Cursor).
func validatePrivateUseScheme(scheme, raw string) error {
	if scheme == "" {
		return fmt.Errorf("redirect URI %q must have a scheme", raw)
	}
	if len(scheme) > 64 {
		return fmt.Errorf("redirect URI %q has an overly long scheme", raw)
	}
	if !isValidURIScheme(scheme) {
		return fmt.Errorf("redirect URI %q has an invalid scheme", raw)
	}
	if deniedRedirectSchemes[strings.ToLower(scheme)] {
		return fmt.Errorf("redirect URI %q uses a disallowed scheme %q", raw, scheme)
	}
	return nil
}

// isValidURIScheme reports whether s matches the RFC 3986 scheme grammar:
// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
func isValidURIScheme(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			// A letter is valid in any position.
		case (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.':
			// Digit / "+" / "-" / "." allowed only after the first character.
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// isLoopbackHost reports whether host is a permitted loopback target for an
// http redirect URI: localhost, 127.0.0.1, or ::1.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

type ClientStore interface {
	StoreClient(client *types.ClientInfo) error
	// CountDynamicClients returns the number of DCR-registered (Dynamic) clients
	// currently stored. It backs the M1 cap check and must be an efficient COUNT,
	// not a load-all.
	CountDynamicClients() (int64, error)
}

// NewHandler builds the /register Dynamic Client Registration handler. When
// enabled is false the handler is mounted but rejects every request with 403
// (see ServeHTTP) so DCR can be turned off without unmounting the route.
//
// maxClients caps how many DCR-registered clients may exist at once (M1): when
// > 0, a registration that would exceed the cap is rejected before storing;
// 0 means unlimited. ttl, when > 0, stamps each newly registered client with an
// expiry of issued_at+ttl so it is later rejected at lookup and garbage-collected
// (M1); 0 means the client never expires.
func NewHandler(db ClientStore, enabled bool, maxClients int, ttl time.Duration) http.Handler {
	return &Handler{
		db:         db,
		enabled:    enabled,
		maxClients: maxClients,
		ttl:        ttl,
	}
}

type Handler struct {
	db         ClientStore
	enabled    bool
	maxClients int
	ttl        time.Duration
}

func (p *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Dynamic Client Registration toggle (F2). When disabled, reject with 403
	// Forbidden so callers can tell the endpoint exists but is turned off
	// (clearer than a 404). Pre-existing stored clients are untouched and keep
	// working for the authorize/token flows.
	if !p.enabled {
		handlerutils.JSON(w, http.StatusForbidden, types.OAuthError{
			Error:            "access_denied",
			ErrorDescription: "dynamic client registration is disabled",
		})
		return
	}

	// Only allow POST method
	if r.Method != "POST" {
		handlerutils.JSON(w, http.StatusMethodNotAllowed, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Method not allowed",
		})
		return
	}

	// Check content length (max 1MB)
	if r.ContentLength > 1024*1024 {
		handlerutils.JSON(w, http.StatusRequestEntityTooLarge, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Request payload too large, must be under 1 MiB",
		})
		return
	}

	// Parse request.JSON body
	var clientMetadata map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&clientMetadata); err != nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request.JSON payload",
		})
		return
	}

	// Validate and extract client metadata
	clientInfo, err := p.validateClientMetadata(clientMetadata)
	if err != nil {
		handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
			Error:            "invalid_client_metadata",
			ErrorDescription: err.Error(),
		})
		return
	}

	// H1 (Fix 1): restrict the redirect URIs accepted at DCR time so a
	// self-registered client cannot use an attacker-controlled redirect target
	// for consent-phishing / auth-code interception. Only https (any host) and
	// loopback http are permitted; fragments, embedded credentials and wildcards
	// are always rejected. Returns invalid_redirect_uri (RFC 7591) with 400.
	for _, uri := range clientInfo.RedirectUris {
		if err := validateRedirectURI(uri); err != nil {
			handlerutils.JSON(w, http.StatusBadRequest, types.OAuthError{
				Error:            "invalid_redirect_uri",
				ErrorDescription: err.Error(),
			})
			return
		}
	}

	// M1 (cap): before storing, reject when the DCR client count is at/over the
	// configured cap so an unauthenticated attacker cannot fill the database. A
	// cap of 0 means unlimited (skip the check). The count is an efficient COUNT,
	// not a load-all. We return 429 Too Many Requests (the registrations are
	// rate/quota-limited) with a clear RFC 7591-style error and do NOT store.
	if p.maxClients > 0 {
		count, err := p.db.CountDynamicClients()
		if err != nil {
			log.Printf("Failed to count dynamic clients: %v", err)
			handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
				Error:            "server_error",
				ErrorDescription: "Failed to register client",
			})
			return
		}
		if count >= int64(p.maxClients) {
			handlerutils.JSON(w, http.StatusTooManyRequests, types.OAuthError{
				Error:            "invalid_client_metadata",
				ErrorDescription: fmt.Sprintf("dynamic client registration limit reached (%d); no new clients can be registered", p.maxClients),
			})
			return
		}
	}

	// Generate client ID and secret
	clientID := encryption.GenerateRandomString(16)
	clientSecret := ""

	// Generate client secret for confidential clients
	if clientInfo.TokenEndpointAuthMethod != "none" {
		clientSecret = encryption.GenerateRandomString(32)
	}

	// Set registration date
	now := time.Now()
	clientInfo.ClientID = clientID
	clientInfo.ClientSecret = clientSecret
	clientInfo.RegistrationDate = now.Unix()

	// M1 (TTL): when a TTL is configured, stamp the client with an expiry of
	// issued_at+ttl so it is rejected at lookup and garbage-collected once stale.
	// A zero TTL leaves ExpiresAt at 0 (never expires), preserving back-compat.
	var expiresAt int64
	if p.ttl > 0 {
		expiresAt = now.Add(p.ttl).Unix()
	}

	// Convert to database.ClientInfo
	dbClientInfo := &types.ClientInfo{
		ClientID:                clientInfo.ClientID,
		ClientSecret:            clientInfo.ClientSecret,
		RedirectUris:            clientInfo.RedirectUris,
		ClientName:              clientInfo.ClientName,
		LogoURI:                 clientInfo.LogoURI,
		ClientURI:               clientInfo.ClientURI,
		PolicyURI:               clientInfo.PolicyURI,
		TosURI:                  clientInfo.TosURI,
		JwksURI:                 clientInfo.JwksURI,
		Contacts:                clientInfo.Contacts,
		GrantTypes:              clientInfo.GrantTypes,
		ResponseTypes:           clientInfo.ResponseTypes,
		RegistrationDate:        clientInfo.RegistrationDate,
		TokenEndpointAuthMethod: clientInfo.TokenEndpointAuthMethod,
		// Mark as DCR-registered so it counts against the cap and is subject to
		// the TTL-based GC; statically provisioned clients keep Dynamic=false.
		Dynamic:   true,
		ExpiresAt: expiresAt,
	}

	// Store client in database
	if err := p.db.StoreClient(dbClientInfo); err != nil {
		log.Printf("Failed to store client: %v", err)
		handlerutils.JSON(w, http.StatusInternalServerError, types.OAuthError{
			Error:            "server_error",
			ErrorDescription: "Failed to register client",
		})
		return
	}

	// Build response
	baseURL := handlerutils.GetBaseURL(r)
	response := map[string]any{
		"client_id":                  clientInfo.ClientID,
		"redirect_uris":              clientInfo.RedirectUris,
		"client_name":                clientInfo.ClientName,
		"logo_uri":                   clientInfo.LogoURI,
		"client_uri":                 clientInfo.ClientURI,
		"policy_uri":                 clientInfo.PolicyURI,
		"tos_uri":                    clientInfo.TosURI,
		"jwks_uri":                   clientInfo.JwksURI,
		"contacts":                   clientInfo.Contacts,
		"grant_types":                clientInfo.GrantTypes,
		"response_types":             clientInfo.ResponseTypes,
		"token_endpoint_auth_method": clientInfo.TokenEndpointAuthMethod,
		"registration_client_uri":    fmt.Sprintf("%s/register/%s", baseURL, clientID),
		"client_id_issued_at":        clientInfo.RegistrationDate,
	}

	// Include client secret in response for confidential clients
	if clientSecret != "" {
		response["client_secret"] = clientSecret
		response["client_secret_expires_at"] = 0 // Never expires
	}

	// Drop empty values
	for k, v := range response {
		if v == "" || v == nil {
			delete(response, k)
		}
	}

	handlerutils.JSON(w, http.StatusOK, response)
}

func (p *Handler) validateClientMetadata(metadata map[string]any) (*types.ClientInfo, error) {
	// Helper function to validate string fields
	validateStringField := func(field any, name string) (string, error) {
		if field == nil {
			return "", nil
		}
		if str, ok := field.(string); ok {
			return str, nil
		}
		return "", fmt.Errorf("field %s must be a string", name)
	}

	// Helper function to validate string arrays
	validateStringArray := func(arr any, name string) ([]string, error) {
		if arr == nil {
			return nil, nil
		}
		if array, ok := arr.([]any); ok {
			result := make([]string, len(array))
			for i, item := range array {
				if str, ok := item.(string); ok {
					result[i] = str
				} else {
					return nil, fmt.Errorf("all elements in %s must be strings", name)
				}
			}
			return result, nil
		}
		return nil, fmt.Errorf("field %s must be an array", name)
	}

	// Validate token_endpoint_auth_method
	authMethod, err := validateStringField(metadata["token_endpoint_auth_method"], "token_endpoint_auth_method")
	if err != nil {
		return nil, err
	}
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}

	// Validate that the auth method is supported
	validAuthMethods := []string{
		"none",
		"client_secret_post",
	}

	isValidAuthMethod := false
	for _, validMethod := range validAuthMethods {
		if authMethod == validMethod {
			isValidAuthMethod = true
			break
		}
	}

	if !isValidAuthMethod {
		return nil, fmt.Errorf("unsupported token_endpoint_auth_method: %s. Supported methods: %v", authMethod, validAuthMethods)
	}

	// Validate redirect_uris (required)
	redirectUris, err := validateStringArray(metadata["redirect_uris"], "redirect_uris")
	if err != nil {
		return nil, err
	}
	if len(redirectUris) == 0 {
		return nil, fmt.Errorf("at least one redirect URI is required")
	}

	// Validate other fields
	clientName, err := validateStringField(metadata["client_name"], "client_name")
	if err != nil {
		return nil, err
	}

	logoURI, err := validateStringField(metadata["logo_uri"], "logo_uri")
	if err != nil {
		return nil, err
	}

	clientURI, err := validateStringField(metadata["client_uri"], "client_uri")
	if err != nil {
		return nil, err
	}

	policyURI, err := validateStringField(metadata["policy_uri"], "policy_uri")
	if err != nil {
		return nil, err
	}

	tosURI, err := validateStringField(metadata["tos_uri"], "tos_uri")
	if err != nil {
		return nil, err
	}

	jwksURI, err := validateStringField(metadata["jwks_uri"], "jwks_uri")
	if err != nil {
		return nil, err
	}

	contacts, err := validateStringArray(metadata["contacts"], "contacts")
	if err != nil {
		return nil, err
	}
	// inspector will check the schema and see if it is null, so this is a workaround
	if len(contacts) == 0 {
		contacts = []string{}
	}

	grantTypes, err := validateStringArray(metadata["grant_types"], "grant_types")
	if err != nil {
		return nil, err
	}
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	responseTypes, err := validateStringArray(metadata["response_types"], "response_types")
	if err != nil {
		return nil, err
	}
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	return &types.ClientInfo{
		RedirectUris:            redirectUris,
		ClientName:              clientName,
		LogoURI:                 logoURI,
		ClientURI:               clientURI,
		PolicyURI:               policyURI,
		TosURI:                  tosURI,
		JwksURI:                 jwksURI,
		Contacts:                contacts,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
	}, nil
}
