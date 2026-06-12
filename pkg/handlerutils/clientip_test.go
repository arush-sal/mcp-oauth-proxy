package handlerutils

import (
	"net/http/httptest"
	"testing"
)

// TestGetClientIPTrustDefault verifies that with NO context value set (absent),
// GetClientIP preserves today's trusting behavior: it honors X-Forwarded-For
// and X-Real-IP.
func TestGetClientIPTrustDefault(t *testing.T) {
	t.Run("AbsentContextHonorsXFF", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7, 70.41.3.18")

		if got := GetClientIP(req); got != "203.0.113.7" {
			t.Fatalf("expected first XFF IP honored (absent => trust), got %q", got)
		}
	})

	t.Run("AbsentContextHonorsXRealIP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Real-IP", "203.0.113.9")

		if got := GetClientIP(req); got != "203.0.113.9" {
			t.Fatalf("expected X-Real-IP honored (absent => trust), got %q", got)
		}
	})
}

// TestGetClientIPTrustTrue verifies that with trust=true in context,
// GetClientIP honors the forwarded headers exactly as the legacy code did.
func TestGetClientIPTrustTrue(t *testing.T) {
	t.Run("HonorsXFF", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7, 70.41.3.18")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetClientIP(req); got != "203.0.113.7" {
			t.Fatalf("expected first XFF IP honored, got %q", got)
		}
	})

	t.Run("HonorsXRealIP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Real-IP", "203.0.113.9")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetClientIP(req); got != "203.0.113.9" {
			t.Fatalf("expected X-Real-IP honored, got %q", got)
		}
	})
}

// TestGetClientIPTrustFalse verifies that with trust=false in context,
// GetClientIP IGNORES the forwarded headers and uses the RemoteAddr host,
// so a spoofed X-Forwarded-For cannot rotate the rate-limit key.
func TestGetClientIPTrustFalse(t *testing.T) {
	t.Run("IgnoresSpoofedXFF", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7, 70.41.3.18")
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("expected spoofed XFF dropped, RemoteAddr host used, got %q", got)
		}
	})

	t.Run("IgnoresXRealIP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Real-IP", "203.0.113.9")
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("expected X-Real-IP dropped, RemoteAddr host used, got %q", got)
		}
	})

	t.Run("RemoteAddrWithoutPort", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.2"
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "10.0.0.2" {
			t.Fatalf("expected RemoteAddr returned verbatim when no port, got %q", got)
		}
	})

	t.Run("IPv6RemoteAddr", func(t *testing.T) {
		// Document the invariant: the host-extraction strips at the LAST colon, so
		// a bracketed IPv6 host:port "[::1]:5555" yields "[::1]".
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "[::1]:5555"
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "[::1]" {
			t.Fatalf("expected IPv6 host extracted as %q, got %q", "[::1]", got)
		}
	})
}
