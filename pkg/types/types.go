package types

import (
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
