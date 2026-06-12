package handlerutils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// trustForwardedKey is the context key under which the resolved
// "trust forwarded headers" policy is stored. Using an unexported struct type
// avoids collisions with other context values.
type trustForwardedKeyType struct{}

var trustForwardedKey = trustForwardedKeyType{}

// WithTrustForwarded returns a copy of ctx carrying whether client-supplied
// forwarded headers (X-Mcp-Oauth-Proxy-URL, X-Forwarded-Proto) should be
// trusted when deriving the external base URL.
func WithTrustForwarded(ctx context.Context, trust bool) context.Context {
	return context.WithValue(ctx, trustForwardedKey, trust)
}

// trustForwardedFromContext reports whether forwarded headers should be
// trusted. When the value is ABSENT, it returns true so any code path or test
// that does not set it preserves today's trusting behavior.
func trustForwardedFromContext(ctx context.Context) bool {
	trust, ok := ctx.Value(trustForwardedKey).(bool)
	if !ok {
		return true
	}
	return trust
}

// trustedProxyURL returns the parsed, trusted X-Mcp-Oauth-Proxy-URL header when
// it is present, trusted, AND a valid absolute URL with both a scheme and a
// host. Otherwise it returns (nil, false): the header is absent, untrusted, or
// malformed and MUST be ignored by both GetBaseURL and requestIsHTTPS so they
// never emit (or imply) a garbage base URL.
func trustedProxyURL(r *http.Request, trust bool) (*url.URL, bool) {
	if !trust {
		return nil, false
	}
	raw := r.Header.Get("X-Mcp-Oauth-Proxy-URL")
	if raw == "" {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		// Malformed / missing scheme or host: treat as absent.
		return nil, false
	}
	return u, true
}

// requestIsHTTPS is the SINGLE SOURCE OF TRUTH for "should this request be
// treated as https". It is shared verbatim by GetBaseURL (scheme selection) and
// by the cookie Secure determination (via RequestIsHTTPS) so the two can never
// disagree. Precedence, evaluated in order:
//
//  1. trusted X-Mcp-Oauth-Proxy-URL (valid absolute URL with a host) -> its
//     scheme is AUTHORITATIVE (https iff scheme == "https"), taking precedence
//     OVER r.TLS. GetBaseURL returns this header verbatim, so an http:// proxy
//     URL means NOT https even when TLS is terminated at this proxy: the
//     operator declared an http external URL; honor it consistently.
//  2. r.TLS != nil               -> https.
//  3. trust AND X-Forwarded-Proto == "https" -> https.
//  4. otherwise                  -> http.
//
// A malformed proxy-URL header is treated as absent (it falls through to TLS /
// XFP). When trust is disabled, both forwarded headers are ignored and only
// r.TLS decides, so a client cannot spoof its way to a Secure cookie or an
// https base URL.
func requestIsHTTPS(r *http.Request, trust bool) bool {
	if u, ok := trustedProxyURL(r, trust); ok {
		return u.Scheme == "https"
	}
	if r.TLS != nil {
		return true
	}
	if trust && r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	return false
}

// RequestIsHTTPS reports whether the request should be treated as https. The
// trust-forwarded policy is read from the request context (see
// WithTrustForwarded); when ABSENT it defaults to true, preserving today's
// trusting behavior. This matches how GetBaseURL reads trust, so a caller can
// never pass a trust value inconsistent with the one GetBaseURL uses.
//
// It is the single source of truth used by GetBaseURL for scheme selection AND
// by the session cookie Secure decision in other packages, so the cookie Secure
// flag and the derived base-URL scheme cannot disagree. See requestIsHTTPS for
// the precedence rule.
func RequestIsHTTPS(r *http.Request) bool {
	return requestIsHTTPS(r, trustForwardedFromContext(r.Context()))
}

func JSON(w http.ResponseWriter, statusCode int, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if obj != nil {
		if err := json.NewEncoder(w).Encode(obj); err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			// Write error response if encoding fails
			errText, _ := json.Marshal(map[string]string{
				"error":             "internal_server_error",
				"error_description": "Failed to encode JSON response",
				"error_detail":      err.Error(),
			})
			_, _ = w.Write(errText)
		}
	}
}

// GetClientIP extracts the client IP from the request. It is the per-IP
// rate-limit key for /authorize, /token, /register, so it MUST honor the
// trust-forwarded policy injected by withCORS (see WithTrustForwarded).
//
// When forwarded headers are trusted (the default and the absent-context
// case), it honors X-Forwarded-For (first entry) then X-Real-IP, preserving the
// historical behavior. When trust is disabled, both client-supplied headers are
// ignored and the IP is derived from r.RemoteAddr (host:port -> host); this
// stops a client from spoofing X-Forwarded-For to rotate the rate-limit key.
func GetClientIP(r *http.Request) string {
	if trustForwardedFromContext(r.Context()) {
		// Check X-Forwarded-For header first
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Get the first IP in the comma-separated list
			ifs := strings.Split(xff, ",")
			return strings.TrimSpace(ifs[0])
		}

		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	// Fall back to RemoteAddr (also the only source when trust is disabled).
	ip := r.RemoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
	}
	return ip
}

// GetBaseURL returns the URL of the request without the path and
// infers the scheme (http or https).
//
// Whether client-supplied forwarded headers are trusted is read from the
// request context (see WithTrustForwarded). When trust is enabled (the default
// and the absent-context case), it honors a valid X-Mcp-Oauth-Proxy-URL verbatim
// (so its scheme is authoritative) and otherwise falls back to the scheme from
// requestIsHTTPS with the host from r.Host. A malformed proxy-URL header (not a
// valid absolute URL with scheme+host) is IGNORED so this function never emits a
// garbage base URL. When trust is disabled, both forwarded headers are ignored:
// the scheme is derived from r.TLS only (https iff r.TLS != nil) and the host
// from r.Host. Note that r.Host is still the client-supplied HTTP Host header,
// so it should be constrained by a fronting reverse proxy / allowed-host config
// at the infrastructure layer.
//
// The scheme this function implies is kept consistent with RequestIsHTTPS for
// the same inputs (both read trust from the context and share trustedProxyURL +
// requestIsHTTPS): returning the trusted proxy-URL header verbatim agrees with
// requestIsHTTPS treating that same header's scheme as authoritative, and the
// fallback path shares requestIsHTTPS directly. So the cookie Secure flag and
// this base URL cannot disagree for any combination of inputs.
func GetBaseURL(r *http.Request) string {
	trust := trustForwardedFromContext(r.Context())

	if u, ok := trustedProxyURL(r, trust); ok {
		return u.String()
	}

	scheme := "http"
	if requestIsHTTPS(r, trust) {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}
