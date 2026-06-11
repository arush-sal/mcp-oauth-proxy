package proxy

import (
	"fmt"
	"log"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

// Allowed values for AUTHORIZATION_HEADER_TOKEN.
const (
	authHeaderTokenNone        = "none"
	authHeaderTokenAccessToken = "access_token"
	authHeaderTokenIDToken     = "id_token"
)

// authorizationHeader is the canonical Authorization header name. The proxy's
// own access-token header is X-Forwarded-Access-Token; the id_token must never
// be configured to land on it.
const (
	authorizationHeader = "Authorization"
	accessTokenHeader   = "X-Forwarded-Access-Token"
)

// Proxy-owned identity headers that setHeaders writes unconditionally from the
// grant props. ID_TOKEN_HEADER must never resolve to one of these: applyForwarding
// runs AFTER setHeaders writes them, so a custom id_token header colliding with
// any of these would overwrite the identity signal with a raw JWT.
const (
	forwardedUserHeader  = "X-Forwarded-User"
	forwardedEmailHeader = "X-Forwarded-Email"
	forwardedNameHeader  = "X-Forwarded-Name"
)

// inboundIdentityHeaders is the canonical set of client-supplied identity /
// forwarded headers stripped from the outbound request when
// STRIP_INBOUND_IDENTITY_HEADERS is enabled (F3). The names mirror oauth2-proxy
// so behavior is familiar. It deliberately EXCLUDES routing/transport headers
// (X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-For, X-Forwarded-Uri):
// those are not identity signals and the proxy Director sets Host/Proto itself.
//
// The proxy-managed four (X-Forwarded-User/Email/Name/Access-Token) and
// Authorization are listed here for an explicit pre-strip, even though
// setHeaders re-derives them afterward; this keeps the stripped set complete and
// self-documenting. The runtime-configured ID_TOKEN_HEADER is added on top of
// this list by stripInboundIdentityHeaders.
var inboundIdentityHeaders = []string{
	authorizationHeader,
	forwardedUserHeader,
	forwardedEmailHeader,
	forwardedNameHeader,
	accessTokenHeader,
	"X-Forwarded-Groups",
	"X-Forwarded-Preferred-Username",
	"X-Forwarded-Preferred-User",
	"X-Forwarded-Auth",
	"X-Auth-Request-User",
	"X-Auth-Request-Email",
	"X-Auth-Request-Groups",
	"X-Auth-Request-Preferred-Username",
	"X-Auth-Request-Access-Token",
	"X-Auth-Request-Authorization",
	"X-Auth-Request-Redirect",
	"X-Remote-User",
	"X-Remote-Email",
	"X-Remote-Groups",
}

// stripInboundIdentityHeaders deletes the full inbound identity / forwarded
// header family (inboundIdentityHeaders) plus the configured ID_TOKEN_HEADER
// from header. It is called from setHeaders BEFORE the proxy writes its own
// derived headers, so legitimately-derived values are written after the strip.
// A spoofed inbound value for any of these headers therefore cannot survive into
// the upstream request.
func (f forwardConfig) stripInboundIdentityHeaders(header http.Header) {
	for _, h := range inboundIdentityHeaders {
		header.Del(h)
	}
	if f.idTokenHeader != "" {
		header.Del(f.idTokenHeader)
	}
}

// forwardConfig is the resolved, validated upstream token-forwarding policy.
// It is derived once at startup from types.Config so the per-request header
// path does not re-parse strings. The zero value means "none": preserve
// today's behavior (no Authorization set, no id_token forwarded).
type forwardConfig struct {
	// authToken selects which token, if any, is written to the Authorization
	// header: authHeaderTokenNone, authHeaderTokenAccessToken, or
	// authHeaderTokenIDToken.
	authToken string
	// idTokenHeader, when non-empty, is the custom header (verbatim, as given)
	// that carries the raw id_token without a "Bearer " prefix. Mutually
	// exclusive with authToken == authHeaderTokenIDToken (enforced at startup).
	idTokenHeader string
}

// resolveForwardConfig validates the raw forwarding settings and returns the
// resolved policy. It rejects ambiguous or colliding configurations with an
// explicit error; there is NO implicit "one wins" behavior.
//
// Collision rules enforced:
//  1. AuthorizationHeaderToken must be one of "" (treated as none), "none",
//     "access_token", or "id_token".
//  2. If IDTokenHeader is set, AuthorizationHeaderToken must NOT also be
//     "id_token": that is two directives for the same destination (the
//     id_token). Pick exactly one mechanism.
//  3. IDTokenHeader must not resolve (case-insensitively) to "Authorization"
//     while AuthorizationHeaderToken is "access_token": both would land on
//     Authorization.
//  4. IDTokenHeader must not resolve to the proxy's own
//     "X-Forwarded-Access-Token" header (which always carries the access
//     token), regardless of AuthorizationHeaderToken.
func resolveForwardConfig(cfg *types.Config) (forwardConfig, error) {
	authToken := strings.TrimSpace(cfg.AuthorizationHeaderToken)
	if authToken == "" {
		authToken = authHeaderTokenNone
	}
	switch authToken {
	case authHeaderTokenNone, authHeaderTokenAccessToken, authHeaderTokenIDToken:
	default:
		return forwardConfig{}, fmt.Errorf(
			"invalid AUTHORIZATION_HEADER_TOKEN %q: must be one of %q, %q, or %q",
			authToken, authHeaderTokenNone, authHeaderTokenAccessToken, authHeaderTokenIDToken,
		)
	}

	idTokenHeader := strings.TrimSpace(cfg.IDTokenHeader)

	if idTokenHeader != "" {
		// Rule 2: two directives for the id_token destination.
		if authToken == authHeaderTokenIDToken {
			return forwardConfig{}, fmt.Errorf(
				"ambiguous id_token forwarding: set EITHER AUTHORIZATION_HEADER_TOKEN=id_token OR ID_TOKEN_HEADER, not both",
			)
		}

		canonical := textproto.CanonicalMIMEHeaderKey(idTokenHeader)

		// Rule 4: never collide with the proxy's access-token header.
		if canonical == accessTokenHeader {
			return forwardConfig{}, fmt.Errorf(
				"ID_TOKEN_HEADER must not be %q: that header always carries the access token",
				accessTokenHeader,
			)
		}

		// Rule 5: never collide with a proxy-owned identity header. setHeaders
		// writes these unconditionally before applyForwarding runs, so a custom
		// id_token header landing here would overwrite the identity signal with
		// a raw JWT.
		switch canonical {
		case forwardedUserHeader, forwardedEmailHeader, forwardedNameHeader:
			return forwardConfig{}, fmt.Errorf(
				"ID_TOKEN_HEADER must not be %q: that header carries the proxy-owned identity signal",
				canonical,
			)
		}

		// Rule 3: id_token -> Authorization while access_token also -> Authorization.
		if canonical == authorizationHeader && authToken == authHeaderTokenAccessToken {
			return forwardConfig{}, fmt.Errorf(
				"ID_TOKEN_HEADER resolves to %q which collides with AUTHORIZATION_HEADER_TOKEN=access_token",
				authorizationHeader,
			)
		}
	}

	return forwardConfig{authToken: authToken, idTokenHeader: idTokenHeader}, nil
}

// applyForwarding writes the configured upstream auth header(s) onto header,
// using the grant props. It MUST be called after any inbound Authorization has
// been deleted so a spoofed inbound value cannot survive.
//
// Behavior by policy:
//   - none: nothing is written (Authorization stays absent; the access token is
//     only ever exposed via X-Forwarded-Access-Token, set by setHeaders).
//   - access_token: "Authorization: Bearer <access_token>".
//   - id_token -> Authorization: "Authorization: Bearer <id_token>".
//   - id_token -> custom header: the raw id_token verbatim (no "Bearer " prefix).
//
// Expiry safety: an absent, malformed, or expired id_token is NEVER forwarded;
// the destination header is left absent. The id_token was already verified when
// stored, so a lightweight unverified exp parse is sufficient (and necessary,
// since verification needs JWKS) to decide staleness here.
func (f forwardConfig) applyForwarding(header http.Header, props map[string]any) {
	switch f.authToken {
	case authHeaderTokenAccessToken:
		if accessToken, ok := props["access_token"].(string); ok && accessToken != "" {
			header.Set(authorizationHeader, "Bearer "+accessToken)
		}
	case authHeaderTokenIDToken:
		f.setIDToken(header, authorizationHeader, props)
	}

	if f.idTokenHeader != "" {
		f.setIDToken(header, f.idTokenHeader, props)
	}
}

// setIDToken writes the (non-stale) id_token to dst. For the Authorization
// header it uses a "Bearer " prefix; any other (custom) header carries the raw
// JWT verbatim. A missing, malformed, or expired id_token is dropped (header
// left absent) and logged at debug level.
func (f forwardConfig) setIDToken(header http.Header, dst string, props map[string]any) {
	// Always clear the destination first so a spoofed inbound value can never
	// survive when no valid, non-stale id_token is written below. setHeaders
	// already deletes Authorization, but deleting again here is harmless and
	// keeps setIDToken self-contained for any custom destination header too.
	header.Del(dst)

	rawIDToken, ok := props["id_token"].(string)
	if !ok || rawIDToken == "" {
		log.Printf("debug: not forwarding id_token: none stored on grant")
		return
	}
	if idTokenExpired(rawIDToken) {
		// F1 refreshes the stored id_token on IdP refresh; if the IdP did not
		// issue a fresh one, forwarding stops here rather than sending a stale
		// token.
		log.Printf("debug: not forwarding id_token to %q: stored token is expired", dst)
		return
	}
	if textproto.CanonicalMIMEHeaderKey(dst) == authorizationHeader {
		header.Set(authorizationHeader, "Bearer "+rawIDToken)
		return
	}
	header.Set(dst, rawIDToken)
}

// idTokenExpired reports whether the JWT's exp is in the past (or cannot be
// parsed). It performs an UNVERIFIED parse of the claims: the token was already
// cryptographically verified by the idtoken verifier when it was stored on the
// grant, so re-verifying here (which would require JWKS) is unnecessary; we only
// need exp to avoid forwarding a stale token. A token that cannot be parsed, or
// has no exp, is treated as expired (fail closed: do not forward).
func idTokenExpired(rawIDToken string) bool {
	if rawIDToken == "" {
		return true
	}
	parser := jwt.NewParser()
	claims := jwt.RegisteredClaims{}
	if _, _, err := parser.ParseUnverified(rawIDToken, &claims); err != nil {
		return true
	}
	if claims.ExpiresAt == nil {
		return true
	}
	return !claims.ExpiresAt.After(time.Now())
}
