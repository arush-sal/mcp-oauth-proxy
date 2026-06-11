// Package idtoken provides verification of OIDC id_tokens issued by the
// upstream identity provider (IdP) and extraction of normalized identity
// claims.
//
// This is shared infrastructure: it verifies an IdP-issued id_token and pulls
// out a small, normalized set of claims (email, groups, hosted domain, etc.)
// so that later features can make authorization decisions on them. It does NOT
// forward anything and does NOT gate any request on its own.
//
// IMPORTANT: this verifier is deliberately separate from the inbound bearer
// token validation in pkg/tokens. That validator trusts tokens against the
// proxy's own TrustedIssuer/TrustedAudiences, which are the WRONG issuer and
// audience for an IdP-issued id_token. An id_token is issued BY the IdP FOR the
// proxy's OAuth client, so it must be validated against the provider's issuer
// and the OAuth client ID as the audience.
package idtoken

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Claims is the normalized subset of OIDC id_token claims that this proxy
// cares about. Fields that are not present in the token are left as their zero
// value; a missing optional claim is not an error.
type Claims struct {
	// Email is the "email" claim.
	Email string `json:"email,omitempty"`
	// EmailVerified is the "email_verified" claim.
	EmailVerified bool `json:"email_verified,omitempty"`
	// Groups is the "groups" claim. Providers send this either as a JSON
	// string (a single group) or as a JSON array of strings; both are
	// normalized to a []string here.
	Groups []string `json:"groups,omitempty"`
	// HostedDomain is the Google "hd" (hosted domain) claim.
	HostedDomain string `json:"hd,omitempty"`
	// Subject is the "sub" claim.
	Subject string `json:"sub,omitempty"`
}

// UnmarshalJSON decodes Claims, tolerating the "groups" claim arriving as
// either a JSON string or a JSON array of strings.
func (c *Claims) UnmarshalJSON(data []byte) error {
	// Decode into a shadow type to avoid recursing into this method, with the
	// flexible groups type substituted in.
	type alias struct {
		Email         string      `json:"email,omitempty"`
		EmailVerified bool        `json:"email_verified,omitempty"`
		Groups        groupsValue `json:"groups,omitempty"`
		HostedDomain  string      `json:"hd,omitempty"`
		Subject       string      `json:"sub,omitempty"`
	}
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	c.Email = a.Email
	c.EmailVerified = a.EmailVerified
	c.Groups = []string(a.Groups)
	c.HostedDomain = a.HostedDomain
	c.Subject = a.Subject
	return nil
}

// groupsValue is a string slice that tolerates a JSON value arriving either as
// a single string or as an array of strings. Keeping it private but distinct
// makes it easy to extend for a future configurable groups-claim name.
type groupsValue []string

// UnmarshalJSON accepts the groups value as either a JSON string or a JSON
// array of strings.
func (g *groupsValue) UnmarshalJSON(data []byte) error {
	// Try array of strings first.
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*g = arr
		return nil
	}

	// Fall back to a single string.
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single == "" {
			*g = nil
			return nil
		}
		*g = []string{single}
		return nil
	}

	return fmt.Errorf("groups claim is neither a string nor an array of strings")
}

// Config holds the parameters required to verify an IdP-issued id_token.
type Config struct {
	// Issuer is the expected "iss" claim value (the provider's issuer).
	Issuer string
	// JWKSURL is the URL of the provider's JWKS endpoint used to fetch and
	// cache the signing keys.
	JWKSURL string
	// Audience is the expected "aud" claim value, which for an id_token is the
	// proxy's OAuth client ID.
	Audience string
	// GroupsClaim is the name of the claim that carries the user's groups. When
	// empty it defaults to the standard "groups" claim. A configured value lets
	// the proxy read groups from a provider-specific claim (e.g. "roles"). The
	// value, like "groups", may be a JSON string or a JSON array of strings.
	GroupsClaim string
	// HTTPClient is an optional HTTP client used to fetch the JWKS. If nil, a
	// default client is used. Primarily a test seam.
	HTTPClient *http.Client
}

// DefaultGroupsClaim is the claim name used to extract groups when no
// GroupsClaim is configured.
const DefaultGroupsClaim = "groups"

// Verifier verifies IdP-issued id_tokens and extracts normalized Claims.
type Verifier struct {
	issuer      string
	audience    string
	groupsClaim string
	keyFunc     keyfunc.Keyfunc
}

// NewVerifier constructs a Verifier that fetches and caches JWKS from
// cfg.JWKSURL. It validates that issuer, JWKS URL, and audience are all set;
// callers that cannot supply these (e.g. non-OIDC setups) should not build a
// Verifier at all and instead treat id_tokens as absent. See MaybeNewVerifier.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("idtoken: issuer is required")
	}
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("idtoken: JWKS URL is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("idtoken: audience is required")
	}

	override := keyfunc.Override{
		HTTPTimeout: 30 * time.Second,
	}
	if cfg.HTTPClient != nil {
		override.Client = cfg.HTTPClient
	}

	kf, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{cfg.JWKSURL}, override)
	if err != nil {
		return nil, fmt.Errorf("idtoken: failed to build JWKS key function: %w", err)
	}

	groupsClaim := cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = DefaultGroupsClaim
	}

	return &Verifier{
		issuer:      cfg.Issuer,
		audience:    cfg.Audience,
		groupsClaim: groupsClaim,
		keyFunc:     kf,
	}, nil
}

// MaybeNewVerifier behaves like NewVerifier but returns (nil, nil) when the
// required OIDC parameters are not all present. This lets callers wire the
// verifier in unconditionally: a nil *Verifier simply means "no id_token
// verification configured", which is the behavior-neutral default for non-OIDC
// setups. A non-nil error is only returned when the parameters ARE present but
// the verifier could not be constructed (e.g. JWKS endpoint unreachable).
func MaybeNewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.JWKSURL == "" || cfg.Audience == "" {
		return nil, nil
	}
	return NewVerifier(ctx, cfg)
}

// Verify verifies the signature, issuer, audience, and expiry of rawIDToken and
// returns the normalized Claims. It NEVER returns claims for a token that fails
// verification. An empty rawIDToken is an error; callers that may not have an
// id_token should check for its presence before calling Verify.
func (v *Verifier) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	if rawIDToken == "" {
		return nil, fmt.Errorf("idtoken: empty id_token")
	}

	parser := jwt.NewParser(
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
	)

	token, err := parser.ParseWithClaims(rawIDToken, &jwtClaims{}, v.keyFunc.KeyfuncCtx(ctx))
	if err != nil {
		return nil, fmt.Errorf("idtoken: verification failed: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("idtoken: token is invalid")
	}

	jc, ok := token.Claims.(*jwtClaims)
	if !ok {
		return nil, fmt.Errorf("idtoken: unexpected claims type")
	}

	groups, err := extractGroups(jc.raw, v.groupsClaim)
	if err != nil {
		return nil, fmt.Errorf("idtoken: %w", err)
	}

	return &Claims{
		Email:         jc.Email,
		EmailVerified: jc.EmailVerified,
		Groups:        groups,
		HostedDomain:  jc.HostedDomain,
		Subject:       jc.Subject,
	}, nil
}

// extractGroups pulls the groups claim named claimName out of the raw claim set
// and normalizes it via groupsValue (tolerating a single string or an array of
// strings). An absent or null claim yields no groups; a malformed value (e.g. a
// mixed-type array) is an error so the caller fails closed rather than silently
// dropping groups.
func extractGroups(raw map[string]json.RawMessage, claimName string) ([]string, error) {
	if claimName == "" {
		claimName = DefaultGroupsClaim
	}
	rawVal, ok := raw[claimName]
	if !ok || len(rawVal) == 0 || string(rawVal) == "null" {
		return nil, nil
	}
	var g groupsValue
	if err := g.UnmarshalJSON(rawVal); err != nil {
		return nil, fmt.Errorf("groups claim %q: %w", claimName, err)
	}
	return []string(g), nil
}

// jwtClaims embeds jwt.RegisteredClaims so the jwt parser validates the
// standard exp/iss/aud claims, and adds the provider-specific identity claims
// this proxy extracts. "sub" is intentionally taken from RegisteredClaims to
// avoid a duplicate JSON tag; it is copied into Claims.Subject afterward. The
// full raw claim set is captured so a configurable groups claim (by name) can be
// extracted after standard validation.
type jwtClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	HostedDomain  string `json:"hd,omitempty"`

	// raw holds every top-level claim so the groups claim can be read by its
	// configured name. It is populated by UnmarshalJSON.
	raw map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON decodes the standard/identity fields via a shadow type (to avoid
// recursion) and also captures the full raw claim set for later by-name groups
// extraction.
func (c *jwtClaims) UnmarshalJSON(data []byte) error {
	type alias jwtClaims
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = jwtClaims(a)

	if err := json.Unmarshal(data, &c.raw); err != nil {
		return err
	}
	return nil
}
