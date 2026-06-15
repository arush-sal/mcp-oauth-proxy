package handlerutils

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

// TestExternalBaseURLAuthoritative verifies that when an EXTERNAL_BASE_URL is
// injected into the request context, GetBaseURL returns it verbatim
// (normalized) and IGNORES a spoofed X-Mcp-Oauth-Proxy-URL and
// X-Forwarded-Proto, regardless of the trust-forwarded policy. RequestIsHTTPS
// derives its scheme from the external base URL so the cookie Secure decision
// matches.
func TestExternalBaseURLAuthoritative(t *testing.T) {
	t.Run("OverridesSpoofedProxyURLWhenTrustTrue", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://spoofed.attacker.example")
		req.Header.Set("X-Forwarded-Proto", "https")
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithExternalBaseURL(ctx, "https://canonical.example")
		req = req.WithContext(ctx)

		if got := GetBaseURL(req); got != "https://canonical.example" {
			t.Fatalf("expected authoritative external base URL, got %q", got)
		}
		if !RequestIsHTTPS(req) {
			t.Fatal("RequestIsHTTPS must derive https from the external base URL")
		}
	})

	t.Run("OverridesSpoofedProxyURLWhenTrustFalse", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://spoofed.attacker.example")
		ctx := WithTrustForwarded(req.Context(), false)
		ctx = WithExternalBaseURL(ctx, "https://canonical.example")
		req = req.WithContext(ctx)

		if got := GetBaseURL(req); got != "https://canonical.example" {
			t.Fatalf("expected authoritative external base URL (trust=false), got %q", got)
		}
		if !RequestIsHTTPS(req) {
			t.Fatal("RequestIsHTTPS must derive https from the external base URL")
		}
	})

	t.Run("HTTPExternalBaseURLOverridesTLS", func(t *testing.T) {
		// An http external base URL means NOT https even when TLS is terminated
		// at this proxy, so the cookie Secure decision matches the declared URL.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.TLS = &tls.ConnectionState{}
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithExternalBaseURL(ctx, "http://canonical.example")
		req = req.WithContext(ctx)

		if got := GetBaseURL(req); got != "http://canonical.example" {
			t.Fatalf("expected http external base URL verbatim, got %q", got)
		}
		if RequestIsHTTPS(req) {
			t.Fatal("RequestIsHTTPS must be false for an http external base URL")
		}
	})

	t.Run("ReturnedVerbatim", func(t *testing.T) {
		// The injected value is the already-normalized origin (the proxy injects
		// types.Config.NormalizedExternalBaseURL); GetBaseURL returns it verbatim.
		// Trailing-slash normalization is asserted at the types layer
		// (TestNormalizedExternalBaseURL).
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req = req.WithContext(WithExternalBaseURL(req.Context(), "https://canonical.example"))

		if got := GetBaseURL(req); got != "https://canonical.example" {
			t.Fatalf("expected external base URL returned verbatim, got %q", got)
		}
	})

	t.Run("NormalizedMixedCaseSchemeIsHTTPS", func(t *testing.T) {
		// HIGH-1: a mixed-case scheme normalized at the types layer (scheme
		// lowercased, host case preserved) must yield a reliable https decision
		// here so the cookie Secure flag and GetBaseURL agree.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req = req.WithContext(WithExternalBaseURL(req.Context(), "https://Example.com"))

		if got := GetBaseURL(req); got != "https://Example.com" {
			t.Fatalf("expected normalized external base URL verbatim, got %q", got)
		}
		if !RequestIsHTTPS(req) {
			t.Fatal("RequestIsHTTPS must be true for an https external base URL with mixed-case host")
		}
	})

	t.Run("UnsetFallsBackToTrustGatedBehavior", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.Host = "internal.example"
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://external.example")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetBaseURL(req); got != "https://external.example" {
			t.Fatalf("unset external base URL must preserve trust-gated behavior, got %q", got)
		}
	})
}
