package handlerutils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

// GetClientIP extracts the client IP from the request using the X-Forwarded-For,
// X-Real-IP and RemoteAddr headers.
func GetClientIP(r *http.Request) string {
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

	// Fall back to RemoteAddr
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
// and the absent-context case), it honors X-Mcp-Oauth-Proxy-URL and then
// X-Forwarded-Proto, preserving the historical behavior. When trust is
// disabled, both forwarded headers are ignored: the scheme is derived from
// r.TLS only (https iff r.TLS != nil) and the host from r.Host. Note that
// r.Host is still the client-supplied HTTP Host header, so it should be
// constrained by a fronting reverse proxy / allowed-host config at the
// infrastructure layer.
func GetBaseURL(r *http.Request) string {
	trust := trustForwardedFromContext(r.Context())

	if trust {
		if url := r.Header.Get("X-Mcp-Oauth-Proxy-URL"); url != "" {
			return url
		}
	}

	scheme := "http"
	if r.TLS != nil || (trust && r.Header.Get("X-Forwarded-Proto") == "https") {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}
