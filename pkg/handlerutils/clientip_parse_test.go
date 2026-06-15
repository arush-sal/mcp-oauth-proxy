package handlerutils

import (
	"net/http/httptest"
	"testing"
)

// TestGetClientIPSafeParse verifies MEDIUM-3: the selected XFF entry and the
// RemoteAddr fallback are returned as a valid IP string. The port is stripped
// with net.SplitHostPort (falling back to the raw value when there is no port)
// and the candidate is validated with netip.ParseAddr. IPv6 is handled
// correctly (bracketed host:port and bare address), and a garbage/unparseable
// XFF entry falls back to the RemoteAddr host parsed the same safe way.
func TestGetClientIPSafeParse(t *testing.T) {
	t.Run("IPv6RemoteAddrBracketedPort", func(t *testing.T) {
		// "[::1]:5555" must yield "::1", not "[::1]".
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "[::1]:5555"
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "::1" {
			t.Fatalf("expected IPv6 host %q, got %q", "::1", got)
		}
	})

	t.Run("IPv6RemoteAddrBare", func(t *testing.T) {
		// A bare IPv6 RemoteAddr with no port must be returned as-is (valid IP).
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "2001:db8::1"
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "2001:db8::1" {
			t.Fatalf("expected bare IPv6 %q, got %q", "2001:db8::1", got)
		}
	})

	t.Run("IPv4RemoteAddrWithPort", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.2:5555"
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "10.0.0.2" {
			t.Fatalf("expected %q, got %q", "10.0.0.2", got)
		}
	})

	t.Run("IPv4RemoteAddrNoPort", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.2"
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "10.0.0.2" {
			t.Fatalf("expected %q, got %q", "10.0.0.2", got)
		}
	})

	t.Run("IPv6XFFEntrySelectedCleanly", func(t *testing.T) {
		// A bare IPv6 XFF entry selected by hop count must be returned cleanly.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "2001:db8::1")
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 1)
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != "2001:db8::1" {
			t.Fatalf("expected IPv6 XFF entry %q, got %q", "2001:db8::1", got)
		}
	})

	t.Run("GarbageXFFEntryFallsBackToRemoteAddr", func(t *testing.T) {
		// An unparseable selected XFF entry must fall back to the RemoteAddr host
		// (parsed safely), since the rate-limit key must be a valid IP.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "not-an-ip")
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 1)
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("garbage XFF entry must fall back to RemoteAddr host, got %q", got)
		}
	})

	t.Run("EmptyXFFEntryFallsBackToRemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "1.2.3.4, , 5.6.7.8")
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 2) // selects the empty middle entry
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("empty selected XFF entry must fall back to RemoteAddr host, got %q", got)
		}
	})
}

// TestGetClientIPMalformedCollapsesToSentinel verifies that when neither the
// selected XFF entry nor the RemoteAddr fallback parses into a valid IP, the key
// collapses to a FIXED sentinel constant rather than the raw, unvalidated string.
// A raw value leaking through would let a client mint distinct spoofed
// rate-limit keys from garbage; the sentinel forces all such input onto one
// shared key.
func TestGetClientIPMalformedCollapsesToSentinel(t *testing.T) {
	t.Run("MalformedRemoteAddrNoXFF", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "garbage"
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != unknownClientIP {
			t.Fatalf("malformed RemoteAddr must collapse to sentinel %q, got %q", unknownClientIP, got)
		}
	})

	t.Run("DistinctGarbageCollapsesToSameKey", func(t *testing.T) {
		req1 := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req1.RemoteAddr = "garbage-one"
		req1 = req1.WithContext(WithTrustForwarded(req1.Context(), false))

		req2 := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req2.RemoteAddr = "garbage-two"
		req2 = req2.WithContext(WithTrustForwarded(req2.Context(), false))

		got1, got2 := GetClientIP(req1), GetClientIP(req2)
		if got1 != unknownClientIP || got2 != unknownClientIP {
			t.Fatalf("distinct garbage must both collapse to sentinel %q, got %q and %q", unknownClientIP, got1, got2)
		}
	})

	t.Run("MalformedSelectedXFFWithMalformedRemoteAddr", func(t *testing.T) {
		// Selected XFF entry is garbage AND RemoteAddr is unparseable: must collapse
		// to the sentinel, never the raw RemoteAddr.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "still-garbage"
		req.Header.Set("X-Forwarded-For", "not-an-ip")
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 1)
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != unknownClientIP {
			t.Fatalf("malformed XFF + malformed RemoteAddr must collapse to sentinel %q, got %q", unknownClientIP, got)
		}
	})

	t.Run("ValidRemoteAddrStillReturnsParsedIP", func(t *testing.T) {
		// Regression guard: a valid RemoteAddr must NOT collapse to the sentinel.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.7:5555"
		req = req.WithContext(WithTrustForwarded(req.Context(), false))

		if got := GetClientIP(req); got != "10.0.0.7" {
			t.Fatalf("valid RemoteAddr must return parsed IP, got %q", got)
		}
	})
}
