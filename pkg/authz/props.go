package authz

import (
	"encoding/json"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
)

// IdentityFromStoredProps reconstructs an Identity from a grant's decrypted
// sensitive props. It prefers the verified id_token claims stored under
// "id_token_claims" (the claims-first source of truth, including their
// EmailVerified state) and falls back to the stored "email" (from the userinfo
// endpoint) when the id_token did not carry one. The stored email's verified
// state is read from the persisted "email_verified" flag (missing => false), so
// an unverified email is NEVER silently promoted to verified on refresh. props
// may be nil. This is used by the refresh re-check to re-authorize a session
// without a fresh id_token.
func IdentityFromStoredProps(props map[string]any) Identity {
	var id Identity
	if props == nil {
		return id
	}

	if raw, ok := props["id_token_claims"].(string); ok && raw != "" {
		var claims idtoken.Claims
		if err := json.Unmarshal([]byte(raw), &claims); err == nil {
			id = IdentityFromClaims(&claims)
		}
	}

	// Fall back to the stored userinfo email when the id_token lacked one. Its
	// verified state comes from the persisted "email_verified" flag (the actual
	// value captured at login); a missing flag is treated as unverified.
	if id.Email == "" {
		if email, ok := props["email"].(string); ok && email != "" {
			verified, _ := props["email_verified"].(bool)
			id = MergeUserInfo(id, email, verified)
		}
	}

	return id
}

// AuthorizeStoredProps re-runs the allowlist against an identity reconstructed
// from a grant's decrypted props. It is the shared re-authorization primitive
// for the refresh paths that have no fresh id_token (internal validate refresh
// and the standard OAuth2 POST /token refresh_token grant). It fails closed: a
// nil authorizer returns ErrDenied (deny, never allow). A returned error of
// ErrDenied means an actual authorization deny; any other error is impossible
// here because reconstruction from props never errors (callers handle their own
// load/decrypt infra errors before calling this).
func AuthorizeStoredProps(a *Authorizer, props map[string]any) error {
	if a == nil {
		return ErrDenied
	}
	return a.Authorize(IdentityFromStoredProps(props))
}
