package handlerutils

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

// TestGetBaseURLTrustDefault verifies that with NO context value set (absent),
// GetBaseURL preserves today's trusting behavior: it honors the
// X-Mcp-Oauth-Proxy-URL header and the X-Forwarded-Proto header.
func TestGetBaseURLTrustDefault(t *testing.T) {
	t.Run("AbsentContextHonorsProxyURLHeader", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://spoofed.attacker.example")

		if got := GetBaseURL(req); got != "https://spoofed.attacker.example" {
			t.Fatalf("expected spoofed URL honored (absent => trust), got %q", got)
		}
	})

	t.Run("AbsentContextHonorsForwardedProto", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.Header.Set("X-Forwarded-Proto", "https")

		if got := GetBaseURL(req); got != "https://internal.example" {
			t.Fatalf("expected https from X-Forwarded-Proto, got %q", got)
		}
	})
}

// TestGetBaseURLTrustTrue verifies that with trust=true in context, GetBaseURL
// behaves exactly as the legacy implementation.
func TestGetBaseURLTrustTrue(t *testing.T) {
	t.Run("HonorsProxyURLHeader", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://external.example")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetBaseURL(req); got != "https://external.example" {
			t.Fatalf("expected proxy URL header honored, got %q", got)
		}
	})

	t.Run("HonorsForwardedProto", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.Header.Set("X-Forwarded-Proto", "https")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetBaseURL(req); got != "https://internal.example" {
			t.Fatalf("expected https from X-Forwarded-Proto, got %q", got)
		}
	})
}

// TestGetBaseURLTrustFalse verifies that with trust=false in context,
// GetBaseURL IGNORES both forwarded headers and derives scheme from r.TLS only
// and host from r.Host.
func TestGetBaseURLTrustFalse(t *testing.T) {
	t.Run("IgnoresSpoofedProxyURLHeader", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://spoofed.attacker.example")
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetBaseURL(req); got != "http://internal.example" {
			t.Fatalf("expected spoofed proxy URL dropped, got %q", got)
		}
	})

	t.Run("IgnoresForwardedProto", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.Header.Set("X-Forwarded-Proto", "https")
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetBaseURL(req); got != "http://internal.example" {
			t.Fatalf("expected X-Forwarded-Proto ignored, got %q", got)
		}
	})

	t.Run("HTTPSOnlyFromTLS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.TLS = &tls.ConnectionState{}
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetBaseURL(req); got != "https://internal.example" {
			t.Fatalf("expected https from r.TLS, got %q", got)
		}
	})
}
