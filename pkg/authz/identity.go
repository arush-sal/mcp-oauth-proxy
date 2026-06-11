package authz

import "github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"

// IdentityFromClaims builds an Identity from verified id_token claims. It is the
// claims-first source of truth for an authorization decision. claims may be nil
// (no id_token / no verifier), in which case a zero Identity is returned and the
// caller relies on the userinfo fallback (MergeUserInfo) for any needed
// attributes.
func IdentityFromClaims(claims *idtoken.Claims) Identity {
	if claims == nil {
		return Identity{}
	}
	return Identity{
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Groups:        claims.Groups,
		HostedDomain:  claims.HostedDomain,
	}
}

// MergeUserInfo fills in identity attributes from the provider userinfo endpoint
// for fields the id_token did not supply. The id_token (claims) is authoritative;
// userinfo only fills gaps. Email is only taken from userinfo when the id_token
// did not provide one, and its verified flag comes from userinfo in that case.
// The userinfo endpoint for the generic provider does not expose groups or
// hosted domain, so those are left untouched and a rule needing them fails closed
// upstream when absent.
func MergeUserInfo(id Identity, email string, emailVerified bool) Identity {
	if id.Email == "" && email != "" {
		id.Email = email
		id.EmailVerified = emailVerified
	}
	return id
}
