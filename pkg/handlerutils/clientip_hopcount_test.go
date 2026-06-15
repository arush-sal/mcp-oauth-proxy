package handlerutils

import (
	"net/http/httptest"
	"testing"
)

// TestGetClientIPHopCount verifies the configurable XFF trusted-hop-count
// semantics. The X-Forwarded-For chain is appended left-to-right; the RIGHTMOST
// entries are added by the closest (trusted) proxies. With N trusted hops the
// real client IP is parts[len(parts)-N]; spoofed client-supplied entries sit to
// the LEFT and are ignored.
func TestGetClientIPHopCount(t *testing.T) {
	// chain: evil (192.0.2.1, client-spoofed), realIP (198.51.100.5, true client
	// as seen by edge), lb (203.0.113.10, added by the closest trusted proxy). The
	// selected entry must be a valid IP (MEDIUM-3), so real IPs are used.
	const (
		evil   = "192.0.2.1"
		realIP = "198.51.100.5"
		lb     = "203.0.113.10"
		chain  = evil + ", " + realIP + ", " + lb
	)

	t.Run("N1_UsesRightmost", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", chain)
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 1)
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != lb {
			t.Fatalf("N=1 must use parts[len-1] (rightmost), got %q", got)
		}
	})

	t.Run("N2_UsesSecondFromRight", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", chain)
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 2)
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != realIP {
			t.Fatalf("N=2 must use parts[len-2], got %q", got)
		}
	})

	t.Run("N1_SpoofedLeftmostIgnored", func(t *testing.T) {
		// Adding an extra spoofed leftmost entry must NOT change the key with N=1.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "192.0.2.2, 192.0.2.3, "+realIP+", "+lb)
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 1)
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != lb {
			t.Fatalf("spoofed leftmost entries must be ignored, got %q", got)
		}
	})

	t.Run("N0_IgnoresXFFUsesRemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", chain)
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 0)
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("N=0 must ignore XFF and use RemoteAddr host, got %q", got)
		}
	})

	t.Run("AbsentHopCountDefaultsToRemoteAddr", func(t *testing.T) {
		// Absent hop count => 0 => RemoteAddr (secure default), even with trust.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", chain)
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("absent hop count must default to RemoteAddr host, got %q", got)
		}
	})

	t.Run("NTooLargeFallsBackToRemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", chain) // 3 entries
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 5) // exceeds entries
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("N exceeding entries must fall back to RemoteAddr, got %q", got)
		}
	})

	t.Run("TrustFalseIgnoresXFFEvenWithHopCount", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", chain)
		ctx := WithTrustForwarded(req.Context(), false)
		ctx = WithXFFTrustedHopCount(ctx, 1)
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("trust=false must ignore XFF regardless of hop count, got %q", got)
		}
	})

	t.Run("DuplicateHeaderLinesJoined", func(t *testing.T) {
		// HIGH-2: a client can send its OWN X-Forwarded-For line and a trusted LB
		// can APPEND a separate line. Header.Get sees only the first (client) line.
		// All field lines must be materialized in order before indexing from the
		// right, so with N=1 the rightmost entry (the LB-appended real client) is
		// chosen and the client's separate line is NOT selected.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Add("X-Forwarded-For", "1.2.3.4")     // client-supplied line
		req.Header.Add("X-Forwarded-For", "203.0.113.7") // LB-appended line
		ctx := WithTrustForwarded(req.Context(), true)
		ctx = WithXFFTrustedHopCount(ctx, 1)
		req = req.WithContext(ctx)

		if got := GetClientIP(req); got != "203.0.113.7" {
			t.Fatalf("N=1 must select the rightmost entry across all header lines, got %q", got)
		}
	})

	t.Run("XRealIPNotSpoofableForKey", func(t *testing.T) {
		// X-Real-IP must NOT be usable to rotate the key under the N-based logic:
		// with N=0 (default) it is ignored and RemoteAddr is used.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Real-IP", "203.0.113.9")
		req = req.WithContext(WithTrustForwarded(req.Context(), true))

		if got := GetClientIP(req); got != "10.0.0.1" {
			t.Fatalf("X-Real-IP must not rotate the key by default, got %q", got)
		}
	})
}
