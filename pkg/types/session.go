package types

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Default session lifetimes. These reproduce the historically hardcoded values
// exactly: a 1 hour access token / cookie and a 30 day refresh token / cookie
// (and grant expiry, which mirrors the refresh lifetime).
const (
	DefaultAccessTTL  = time.Hour       // 3600s
	DefaultRefreshTTL = 720 * time.Hour // 30 days = 2592000s
)

// CookieSecureMode is the tri-state policy for the cookie Secure attribute.
type CookieSecureMode int

const (
	// CookieSecureAuto sets Secure only when the request is detected as HTTPS
	// (the historical behavior, via isSecureRequest).
	CookieSecureAuto CookieSecureMode = iota
	// CookieSecureAlways forces Secure on every cookie.
	CookieSecureAlways
	// CookieSecureNever never sets Secure.
	CookieSecureNever
)

// SessionConfig is the resolved, validated session/cookie policy. It is built
// once at startup by ResolveSessionConfig and threaded into the callback
// handler, token handler, and token validator.
type SessionConfig struct {
	// AccessTTL is the access-token / access-cookie lifetime. It also drives the
	// token response ExpiresIn (in seconds) and the access cookie MaxAge.
	AccessTTL time.Duration
	// RefreshTTL is the refresh-token / refresh-cookie lifetime. It also drives
	// the refresh cookie MaxAge and the grant expiry (which mirrors the refresh
	// token lifetime, as it did historically).
	RefreshTTL time.Duration
	// CookieSecure is the tri-state Secure policy.
	CookieSecure CookieSecureMode
	// SameSite is the SameSite mode applied uniformly to all session cookies.
	SameSite http.SameSite
}

// SecureForRequest maps this tri-state Secure policy over a pre-resolved
// "is this request https" bool: Always => true, Never => false, Auto =>
// requestIsHTTPS.
//
// requestIsHTTPS is computed by the caller via handlerutils.RequestIsHTTPS,
// which is the SINGLE SOURCE OF TRUTH for the https decision (it accounts for
// r.TLS, the trusted X-Mcp-Oauth-Proxy-URL scheme, and X-Forwarded-Proto). This
// package deliberately does not import handlerutils (to keep the foundational
// types package dependency-free) and no longer re-derives any part of that rule
// itself, so the cookie Secure flag and the handlerutils-derived base URL cannot
// drift apart.
func (sc SessionConfig) SecureForRequest(requestIsHTTPS bool) bool {
	switch sc.CookieSecure {
	case CookieSecureAlways:
		return true
	case CookieSecureNever:
		return false
	default: // CookieSecureAuto
		return requestIsHTTPS
	}
}

// AccessTTLSeconds returns the access lifetime in whole seconds (for cookie
// MaxAge and token ExpiresIn).
func (sc SessionConfig) AccessTTLSeconds() int {
	return int(sc.AccessTTL.Seconds())
}

// RefreshTTLSeconds returns the refresh lifetime in whole seconds (for cookie
// MaxAge).
func (sc SessionConfig) RefreshTTLSeconds() int {
	return int(sc.RefreshTTL.Seconds())
}

// ResolveSessionConfig validates the raw cookie/session config strings and
// produces a resolved SessionConfig. Defaults reproduce the previously
// hardcoded behavior exactly. Durations are parsed with time.ParseDuration
// (Go duration strings, e.g. "30m", "2h") and must be strictly positive.
func ResolveSessionConfig(cfg *Config) (SessionConfig, error) {
	sc := SessionConfig{
		AccessTTL:    DefaultAccessTTL,
		RefreshTTL:   DefaultRefreshTTL,
		CookieSecure: CookieSecureAuto,
		SameSite:     http.SameSiteLaxMode,
	}

	if raw := strings.TrimSpace(cfg.CookieExpire); raw != "" {
		d, err := parsePositiveDuration("COOKIE_EXPIRE", raw)
		if err != nil {
			return SessionConfig{}, err
		}
		sc.AccessTTL = d
	}

	if raw := strings.TrimSpace(cfg.CookieRefresh); raw != "" {
		d, err := parsePositiveDuration("COOKIE_REFRESH", raw)
		if err != nil {
			return SessionConfig{}, err
		}
		sc.RefreshTTL = d
	}

	if raw := strings.TrimSpace(cfg.CookieSecure); raw != "" {
		switch strings.ToLower(raw) {
		case "auto":
			sc.CookieSecure = CookieSecureAuto
		case "true":
			sc.CookieSecure = CookieSecureAlways
		case "false":
			sc.CookieSecure = CookieSecureNever
		default:
			return SessionConfig{}, fmt.Errorf("invalid COOKIE_SECURE %q: must be one of auto, true, false", raw)
		}
	}

	if raw := strings.TrimSpace(cfg.CookieSameSite); raw != "" {
		switch strings.ToLower(raw) {
		case "lax":
			sc.SameSite = http.SameSiteLaxMode
		case "strict":
			sc.SameSite = http.SameSiteStrictMode
		case "none":
			sc.SameSite = http.SameSiteNoneMode
		default:
			return SessionConfig{}, fmt.Errorf("invalid COOKIE_SAMESITE %q: must be one of lax, strict, none", raw)
		}
	}

	// SameSite=None requires Secure cookies per the cookie spec. "auto" cannot
	// guarantee Secure (it depends on the request), so only "true" is acceptable
	// alongside None.
	if sc.SameSite == http.SameSiteNoneMode && sc.CookieSecure != CookieSecureAlways {
		return SessionConfig{}, fmt.Errorf("COOKIE_SAMESITE=none requires COOKIE_SECURE=true (SameSite=None cookies must be Secure)")
	}

	return sc, nil
}

func parsePositiveDuration(name, raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: must be a Go duration string such as 30m, 1h, 720h: %w", name, raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid %s %q: must be a positive duration", name, raw)
	}
	// Floor at 1s: sub-second values are positive but truncate to 0 whole
	// seconds (AccessTTLSeconds/RefreshTTLSeconds use int(d.Seconds())), which
	// would produce a session cookie (MaxAge:0) and a DB ExpiresAt in the past.
	if d < time.Second {
		return 0, fmt.Errorf("invalid %s %q: must be at least 1s", name, raw)
	}
	return d, nil
}
