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

// TestGetBaseURLTrustedHTTPProxyURLOverridesTLS is BLOCKER 1 at the GetBaseURL
// level: with r.TLS set and a trusted http:// proxy-URL, GetBaseURL returns the
// http:// external URL verbatim (the operator declared an http external URL),
// and RequestIsHTTPS must agree (NOT https) so the cookie Secure flag matches.
func TestGetBaseURLTrustedHTTPProxyURLOverridesTLS(t *testing.T) {
	req := httptest.NewRequest("GET", "http://internal.example/path", nil)
	req.Host = "internal.example"
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("X-Mcp-Oauth-Proxy-URL", "http://ext.example")
	req = req.WithContext(WithTrustForwarded(req.Context(), true))

	if got := GetBaseURL(req); got != "http://ext.example" {
		t.Fatalf("expected http external URL honored verbatim, got %q", got)
	}
	if RequestIsHTTPS(req) {
		t.Fatal("RequestIsHTTPS must agree: trusted http proxy-URL over TLS => http")
	}
}

// TestGetBaseURLMalformedProxyURLIgnored is MINOR 1: a trusted but malformed
// proxy-URL (not a valid absolute URL with scheme+host) must be IGNORED so
// GetBaseURL never emits a garbage base URL; it falls through to the computed
// scheme + r.Host. RequestIsHTTPS treats the malformed header as absent too.
func TestGetBaseURLMalformedProxyURLIgnored(t *testing.T) {
	t.Run("MissingSchemeAndHost_FallsThroughToHTTP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.TLS = nil
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "garbage-no-scheme")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetBaseURL(req); got != "http://internal.example" {
			t.Fatalf("expected malformed header ignored, got %q", got)
		}
		if RequestIsHTTPS(req) {
			t.Fatal("malformed header must be treated as absent: no signal => http")
		}
	})

	t.Run("MissingHost_FallsThroughToTLS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetBaseURL(req); got != "https://internal.example" {
			t.Fatalf("expected malformed header ignored, fall through to TLS+host, got %q", got)
		}
		if !RequestIsHTTPS(req) {
			t.Fatal("malformed header treated as absent: r.TLS => https")
		}
	})
}
