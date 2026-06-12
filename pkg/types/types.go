package types

import (
	"fmt"
	"strings"
	"time"
)

const (
	AccessTokenCookieName  = "access_token"
	RefreshTokenCookieName = "refresh_token"
)

// Config holds all configuration values for the OAuth proxy
type Config struct {
	Port                 string
	DatabaseDSN          string
	OAuthClientID        string
	OAuthClientSecret    string
	OAuthAuthorizeURL    string
	OAuthJWKSURL         string
	TrustedIssuer        string
	TrustedAudiences     []string
	ScopesSupported      string
	EncryptionKey        string
	MCPServerURL         string
	Mode                 string
	RoutePrefix          string
	CookieNamePrefix     string
	MCPPaths             []string
	APIKeyAuthWebhookURL string
	MCPServerID          string

	// OAuthIssuerURL, when set, is the expected id_token "iss" value. It
	// overrides the issuer derived from OAuthAuthorizeURL's origin, which is
	// required for path-based issuers (e.g. Keycloak https://host/realms/x).
	OAuthIssuerURL string

	// Authorization / allowlist (oauth2-proxy parity). With NONE of these set,
	// the proxy DENIES ALL authenticated users (fail-closed breaking-change
	// default). See pkg/authz.
	AllowedEmails              []string // explicit allowed email addresses
	AllowedEmailsFile          string   // path to a file of allowed emails (one per line)
	AllowedEmailDomains        []string // allowed email domains; "*" allows any authenticated user
	AllowedGroups              []string // allowed groups (intersection with the user's groups)
	GroupsClaim                string   // id_token claim carrying groups (default "groups")
	AllowedGoogleHostedDomains []string // allowed Google hosted domains ("hd" claim)

	// Upstream token forwarding (F4f). Controls whether/how the VERIFIED OIDC
	// id_token (or the access token) is forwarded to the upstream MCP server.
	//
	// AuthorizationHeaderToken selects which token is placed on the upstream
	// request: "none" (default; no Authorization set, current behavior),
	// "access_token" (Authorization: Bearer <access_token>), or "id_token"
	// (forward the verified id_token, see IDTokenHeader for the destination).
	//
	// IDTokenHeader optionally names a custom header to carry the raw id_token
	// (without a "Bearer " prefix). When empty and id_token forwarding is
	// active, the id_token is sent as "Authorization: Bearer <id_token>".
	AuthorizationHeaderToken string
	IDTokenHeader            string

	// StripInboundIdentityHeaders (F3) toggles inbound header hygiene. When true,
	// the proxy DELETES the full family of client-supplied identity / forwarded
	// headers from the outbound (upstream) request before writing its own, so a
	// caller cannot spoof identity to an upstream that trusts headers the proxy
	// does not otherwise manage (e.g. X-Forwarded-Groups, X-Auth-Request-*). The
	// runtime-configured IDTokenHeader is included in the stripped set. Default
	// false preserves current behavior: only the four proxy-managed X-Forwarded-*
	// headers + Authorization are neutralized.
	StripInboundIdentityHeaders bool

	// Session & cookie lifetime / security (F5). These are RAW, unparsed
	// strings resolved once at startup by ResolveSessionConfig into a
	// SessionConfig. Empty values fall back to defaults that reproduce the
	// historical hardcoded behavior exactly.
	//
	// CookieExpire is the access-token / access-cookie lifetime (Go duration
	// string, default "1h"). CookieRefresh is the refresh-token / refresh-cookie
	// lifetime AND the grant expiry (Go duration string, default "720h").
	// CookieSecure is tri-state: "auto" (default), "true", "false". CookieSameSite
	// is one of "lax" (default), "strict", "none"; "none" requires CookieSecure
	// "true".
	CookieExpire   string
	CookieRefresh  string
	CookieSecure   string
	CookieSameSite string

	// Health & metrics endpoints (F6). Kubernetes-style liveness/readiness
	// probes plus optional Prometheus metrics. Defaults preserve existing
	// behavior: probes are always on at root paths, metrics are off.
	//
	// HealthPath is the liveness path (default "/healthz"); it returns 200
	// unconditionally. ReadyPath is the readiness path (default "/readyz"); it
	// checks the DB and returns 200/503. The legacy "/health" route remains an
	// alias of liveness for back-compat. EnableMetrics turns on a Prometheus
	// handler. MetricsPath is its path (default "/metrics"). MetricsAddress,
	// when non-empty (e.g. ":9090"), serves metrics on a SEPARATE listener at
	// that address instead of the main mux; when empty and EnableMetrics is
	// true, metrics are mounted on the main mux at MetricsPath.
	HealthPath     string
	ReadyPath      string
	EnableMetrics  bool
	MetricsPath    string
	MetricsAddress string

	// Dynamic Client Registration (DCR) toggle (F2). Controls whether the
	// /register endpoint accepts new client registrations and whether the
	// authorization-server metadata advertises a registration_endpoint.
	//
	// It is a tri-state pointer so an unset value (nil) preserves today's
	// behavior (DCR ENABLED). Resolve it through DCREnabled(), never read the
	// pointer directly. When disabled, /register returns 403 and metadata omits
	// the registration endpoint; pre-existing stored clients keep working.
	EnableDynamicClientRegistration *bool

	// TrustForwardedHeaders controls whether client-supplied forwarded headers
	// (X-Mcp-Oauth-Proxy-URL, X-Forwarded-Proto) are trusted when deriving the
	// external base URL, which feeds redirect URIs, OAuth metadata, and the
	// resource_metadata in the WWW-Authenticate challenge.
	//
	// It is a tri-state pointer so an unset value (nil) preserves today's
	// behavior (forwarded headers TRUSTED). Resolve it through
	// TrustForwardedHeadersEnabled(), never read the pointer directly. Set it to
	// false when the proxy is NOT behind a trusted reverse proxy: the proxy then
	// does NOT trust those forwarded headers and derives the external base URL
	// from the connection (TLS) and the request Host header. Note that the Host
	// header itself should be constrained by a fronting reverse proxy /
	// allowed-host config at the infrastructure layer.
	TrustForwardedHeaders *bool
}

// DCREnabled reports whether Dynamic Client Registration is enabled. An unset
// (nil) value defaults to true so existing configs preserve today's behavior.
func (c *Config) DCREnabled() bool {
	return c.EnableDynamicClientRegistration == nil || *c.EnableDynamicClientRegistration
}

// TrustForwardedHeadersEnabled reports whether client-supplied forwarded
// headers should be trusted when deriving the external base URL. An unset
// (nil) value defaults to true so existing configs preserve today's behavior.
func (c *Config) TrustForwardedHeadersEnabled() bool {
	return c.TrustForwardedHeaders == nil || *c.TrustForwardedHeaders
}

// HealthMetricsConfig is the resolved health/metrics policy derived from the
// raw Config fields. It centralizes default resolution and the "where do
// metrics live" decision so both the route wiring and the cmd-layer listener
// startup agree without duplicating logic.
type HealthMetricsConfig struct {
	HealthPath     string
	ReadyPath      string
	EnableMetrics  bool
	MetricsPath    string
	MetricsAddress string
}

// MetricsOnMainMux reports whether the metrics handler should be registered on
// the main server mux. This is true only when metrics are enabled AND no
// separate MetricsAddress is configured.
func (h HealthMetricsConfig) MetricsOnMainMux() bool {
	return h.EnableMetrics && h.MetricsAddress == ""
}

// MetricsOnSeparateListener reports whether a dedicated metrics listener should
// be started. This is true only when metrics are enabled AND a MetricsAddress
// is configured.
func (h HealthMetricsConfig) MetricsOnSeparateListener() bool {
	return h.EnableMetrics && h.MetricsAddress != ""
}

// ResolveHealthMetricsConfig applies defaults to the raw health/metrics config
// fields. Empty paths fall back to the Kubernetes-style defaults. It never
// errors: all combinations are valid (the empty-vs-set MetricsAddress decision
// is expressed through the MetricsOn* helpers).
func ResolveHealthMetricsConfig(c *Config) HealthMetricsConfig {
	h := HealthMetricsConfig{
		HealthPath:     c.HealthPath,
		ReadyPath:      c.ReadyPath,
		EnableMetrics:  c.EnableMetrics,
		MetricsPath:    c.MetricsPath,
		MetricsAddress: c.MetricsAddress,
	}
	if h.HealthPath == "" {
		h.HealthPath = "/healthz"
	}
	if h.ReadyPath == "" {
		h.ReadyPath = "/readyz"
	}
	if h.MetricsPath == "" {
		h.MetricsPath = "/metrics"
	}
	return h
}

// Validate checks the resolved health/metrics policy for path collisions and
// malformed paths that would otherwise panic http.ServeMux at route setup.
// Call it on the result of ResolveHealthMetricsConfig so defaults are already
// applied. routePrefix is the configured RoutePrefix (may be ""); it is needed
// to detect collisions with the legacy "<routePrefix>/health" liveness route
// that SetupRoutes also registers on the main mux. It enforces:
//   - HealthPath, ReadyPath (and MetricsPath when metrics are enabled) must be
//     absolute paths beginning with "/".
//   - HealthPath != ReadyPath (both always register on the main mux).
//   - When metrics share the main mux (EnableMetrics && MetricsAddress==""),
//     MetricsPath must not collide with HealthPath or ReadyPath. On a separate
//     listener the metrics path lives on its own mux, so a collision is allowed.
//   - The legacy "<routePrefix>/health" route must not collide with ReadyPath
//     or (on the main mux) MetricsPath. A collision with HealthPath is allowed:
//     the liveness probe serves that exact path, so SetupRoutes simply skips the
//     duplicate legacy registration (back-compat is preserved).
func (h HealthMetricsConfig) Validate(routePrefix string) error {
	if !strings.HasPrefix(h.HealthPath, "/") {
		return fmt.Errorf("health path %q must be an absolute path starting with %q", h.HealthPath, "/")
	}
	if !strings.HasPrefix(h.ReadyPath, "/") {
		return fmt.Errorf("ready path %q must be an absolute path starting with %q", h.ReadyPath, "/")
	}
	if h.HealthPath == h.ReadyPath {
		return fmt.Errorf("health path and ready path must differ (both set to %q)", h.HealthPath)
	}
	if h.EnableMetrics {
		if !strings.HasPrefix(h.MetricsPath, "/") {
			return fmt.Errorf("metrics path %q must be an absolute path starting with %q", h.MetricsPath, "/")
		}
		if h.MetricsOnMainMux() {
			if h.MetricsPath == h.HealthPath {
				return fmt.Errorf("metrics path %q collides with health path on the main mux", h.MetricsPath)
			}
			if h.MetricsPath == h.ReadyPath {
				return fmt.Errorf("metrics path %q collides with ready path on the main mux", h.MetricsPath)
			}
		}
	}
	// The legacy liveness route registered by SetupRoutes is fully qualified as
	// routePrefix + "/health". A collision with HealthPath is benign (deduped),
	// but a collision with ReadyPath or main-mux MetricsPath would map two
	// different handlers onto one pattern and panic http.ServeMux.
	legacyHealth := routePrefix + "/health"
	if legacyHealth == h.ReadyPath {
		return fmt.Errorf("legacy health route %q collides with ready path on the main mux", legacyHealth)
	}
	if h.MetricsOnMainMux() && legacyHealth == h.MetricsPath {
		return fmt.Errorf("legacy health route %q collides with metrics path on the main mux", legacyHealth)
	}
	return nil
}

// TokenData represents stored token data for OAuth 2.1 compliance
type TokenData struct {
	AccessToken           string `gorm:"primaryKey"`
	RefreshToken          string `gorm:"uniqueIndex"`
	ClientID              string `gorm:"not null;index"`
	UserID                string `gorm:"not null"`
	GrantID               string `gorm:"not null"`
	Scope                 string
	ExpiresAt             time.Time `gorm:"not null;index"`
	RefreshTokenExpiresAt time.Time `gorm:"not null"`
	CreatedAt             time.Time `gorm:"autoCreateTime"`
	Revoked               bool      `gorm:"default:false;index"`
	RevokedAt             *time.Time
}

// Grant represents an authorization grant
type Grant struct {
	ID                  string      `gorm:"primaryKey" json:"id"`
	ClientID            string      `gorm:"not null;index" json:"client_id"`
	UserID              string      `gorm:"not null;index" json:"user_id"`
	Scope               StringSlice `gorm:"type:text" json:"scope"`
	Metadata            JSON        `gorm:"type:text" json:"metadata"`
	Props               JSON        `gorm:"type:text" json:"props"`
	CreatedAt           int64       `gorm:"not null" json:"created_at"`
	ExpiresAt           int64       `gorm:"not null" json:"expires_at"`
	CodeChallenge       string      `json:"code_challenge,omitempty"`
	CodeChallengeMethod string      `json:"code_challenge_method,omitempty"`
}

// AuthorizationCode represents an authorization code
type AuthorizationCode struct {
	Code      string    `gorm:"primaryKey"`
	GrantID   string    `gorm:"not null"`
	UserID    string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

// StoredAuthRequest represents a stored OAuth authorization request for state management
type StoredAuthRequest struct {
	Key       string    `gorm:"primaryKey"`
	Data      JSON      `gorm:"type:jsonb;not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}
