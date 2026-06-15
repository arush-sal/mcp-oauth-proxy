package handlerutils

import (
	"net/http/httptest"
	"testing"
)

// TestGetClientIPTrustDefault verifies the SECURE default: with NO hop count in
// context (absent => N=0), GetClientIP ignores X-Forwarded-For / X-Real-IP for
// the rate-limit key and uses RemoteAddr, so a single spoofed XFF cannot rotate
// the key. The trust flag alone is not enough; operators must opt in with
// XFF_TRUSTED_HOP_COUNT. See clientip_hopcount_test.go for the N>0 behavior.
func TestGetClientIPTrustDefault(t *testing.T) {
	t.Run("AbsentHopCountIgnoresXFF", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7, 70.41.3.18")

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("expected RemoteAddr host (absent hop count => N=0), got %q", got)
		}
	})

	t.Run("AbsentHopCountIgnoresXRealIP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Real-IP", "203.0.113.9")

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("expected RemoteAddr host (absent hop count => N=0), got %q", got)
		}
	})
}

// TestGetClientIPTrustTrue verifies that trust=true alone (with the default
// hop count of 0) is NOT sufficient to honor the forwarded headers for the key:
// they remain ignored until an operator sets a positive hop count.
func TestGetClientIPTrustTrue(t *testing.T) {
	t.Run("TrustWithoutHopCountIgnoresXFF", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.7, 70.41.3.18")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("expected RemoteAddr host (trust=true, N=0), got %q", got)
		}
	})

	t.Run("TrustWithoutHopCountIgnoresXRealIP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Real-IP", "203.0.113.9")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("expected RemoteAddr host (trust=true, N=0), got %q", got)
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
		// MEDIUM-3: a bracketed IPv6 host:port "[::1]:5555" is parsed safely into
		// the bare canonical address "::1" (net.SplitHostPort + netip.ParseAddr),
		// not the mangled "[::1]" a naive last-colon strip would produce.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "[::1]:5555"
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "::1" {
			t.Fatalf("expected IPv6 host extracted as %q, got %q", "::1", got)
		}
	})
}
