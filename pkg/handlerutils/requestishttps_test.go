package handlerutils

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withTrust returns r carrying the given trust-forwarded policy in its context,
// mirroring how withCORS injects the policy before the handlers run.
func withTrust(r *http.Request, trust bool) *http.Request {
	return r.WithContext(WithTrustForwarded(r.Context(), trust))
}

// TestRequestIsHTTPS_ProxyURLBlocker is the peer-review blocker case: a trusted
// X-Mcp-Oauth-Proxy-URL with an https scheme on a plain-HTTP request (no TLS, no
// X-Forwarded-Proto) MUST report https so the cookie Secure flag matches the
// https base URL GetBaseURL returns. With trust disabled the header is ignored.
func TestRequestIsHTTPS_ProxyURLBlocker(t *testing.T) {
	t.Run("TrustedHTTPSProxyURL_OnPlainHTTP_IsHTTPS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = nil
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://ext.example")

		if !RequestIsHTTPS(withTrust(req, true)) {
			t.Fatal("trusted https X-Mcp-Oauth-Proxy-URL must report https even without TLS/XFP")
		}
	})

	t.Run("Untrusted_IgnoresProxyURL", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = nil
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://ext.example")

		if RequestIsHTTPS(withTrust(req, false)) {
			t.Fatal("untrusted X-Mcp-Oauth-Proxy-URL must be ignored")
		}
	})

	t.Run("TrustedHTTPProxyURL_IsAuthoritativeNotHTTPS", func(t *testing.T) {
		// A trusted proxy-URL header is authoritative for the scheme: an http://
		// proxy URL means NOT https, even if a (spoofable) XFP says https.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = nil
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "http://ext.example")
		req.Header.Set("X-Forwarded-Proto", "https")

		if RequestIsHTTPS(withTrust(req, true)) {
			t.Fatal("trusted http X-Mcp-Oauth-Proxy-URL is authoritative: must report http")
		}
	})

	t.Run("TrustedHTTPProxyURL_OverridesTLS_NotHTTPS", func(t *testing.T) {
		// BLOCKER 1: the trusted proxy-URL scheme is authoritative OVER r.TLS.
		// TLS terminated at this proxy + a trusted http:// external URL means the
		// operator declared an http external URL; honor it (NOT https) so the
		// cookie Secure flag matches the http base URL.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "http://ext.example")

		if RequestIsHTTPS(withTrust(req, true)) {
			t.Fatal("trusted http X-Mcp-Oauth-Proxy-URL must take precedence over r.TLS: report http")
		}
	})

	t.Run("MalformedProxyURL_IgnoredFallsThroughToTLS", func(t *testing.T) {
		// MINOR 1: a trusted but malformed proxy-URL (no scheme/host) must be
		// ignored and fall through to the remaining signals (here r.TLS => https).
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "::::not a url::::")

		if !RequestIsHTTPS(withTrust(req, true)) {
			t.Fatal("malformed proxy-URL must be ignored; r.TLS must then make it https")
		}
	})

	t.Run("MalformedProxyURL_IgnoredFallsThroughToHTTP", func(t *testing.T) {
		// MINOR 1: malformed proxy-URL, no TLS, no XFP => plain http.
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = nil
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "://missing-scheme")

		if RequestIsHTTPS(withTrust(req, true)) {
			t.Fatal("malformed proxy-URL must be ignored; no other signal => http")
		}
	})

	t.Run("TLSAlwaysHTTPSWhenNoTrustedProxyURL", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = &tls.ConnectionState{}
		if !RequestIsHTTPS(withTrust(req, false)) {
			t.Fatal("r.TLS != nil must report https when no authoritative trusted proxy-URL")
		}
	})

	t.Run("TrustedXFPHTTPS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = nil
		req.Header.Set("X-Forwarded-Proto", "https")
		if !RequestIsHTTPS(withTrust(req, true)) {
			t.Fatal("trusted X-Forwarded-Proto: https must report https")
		}
		if RequestIsHTTPS(withTrust(req, false)) {
			t.Fatal("untrusted X-Forwarded-Proto must be ignored")
		}
	})

	t.Run("PlainHTTP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = nil
		if RequestIsHTTPS(withTrust(req, true)) {
			t.Fatal("plain HTTP with no signals must report http")
		}
		if RequestIsHTTPS(withTrust(req, false)) {
			t.Fatal("plain HTTP with no signals must report http")
		}
	})

	t.Run("AbsentContextTrusts", func(t *testing.T) {
		// Absent trust context => trust=true (preserves historical behavior).
		req := httptest.NewRequest("GET", "http://internal.example/path", nil)
		req.TLS = nil
		req.Header.Set("X-Mcp-Oauth-Proxy-URL", "https://ext.example")
		if !RequestIsHTTPS(req) {
			t.Fatal("absent trust context must default to trust=true and honor https proxy-URL")
		}
	})
}

// TestRequestIsHTTPS_ConsistentWithGetBaseURL asserts that for the SAME request
// the scheme implied by GetBaseURL agrees with RequestIsHTTPS across an
// EXHAUSTIVE matrix of {TLS on/off} x {trust on/off} x {proxyURL none/http/https}
// x {XFP none/https}. These are the two consumers that must never disagree (the
// blocker). This is the real regression guard for BLOCKER 1.
func TestRequestIsHTTPS_ConsistentWithGetBaseURL(t *testing.T) {
	tlsOpts := []bool{false, true}
	trustOpts := []bool{false, true}
	proxyOpts := []string{"", "http://ext.example", "https://ext.example"}
	xfpOpts := []string{"", "https"}

	for _, useTLS := range tlsOpts {
		for _, trust := range trustOpts {
			for _, proxyURL := range proxyOpts {
				for _, xfp := range xfpOpts {
					name := matrixName(useTLS, trust, proxyURL, xfp)
					t.Run(name, func(t *testing.T) {
						req := httptest.NewRequest("GET", "http://internal.example/path", nil)
						req.Host = "internal.example"
						req.TLS = nil
						if useTLS {
							req.TLS = &tls.ConnectionState{}
						}
						if xfp != "" {
							req.Header.Set("X-Forwarded-Proto", xfp)
						}
						if proxyURL != "" {
							req.Header.Set("X-Mcp-Oauth-Proxy-URL", proxyURL)
						}
						req = withTrust(req, trust)

						base := GetBaseURL(req)
						baseIsHTTPS := strings.HasPrefix(base, "https://")
						if got := RequestIsHTTPS(req); got != baseIsHTTPS {
							t.Fatalf("scheme disagreement: GetBaseURL=%q (https=%v) but RequestIsHTTPS=%v",
								base, baseIsHTTPS, got)
						}
					})
				}
			}
		}
	}
}

func matrixName(useTLS, trust bool, proxyURL, xfp string) string {
	var b strings.Builder
	if useTLS {
		b.WriteString("tls")
	} else {
		b.WriteString("notls")
	}
	if trust {
		b.WriteString("/trust")
	} else {
		b.WriteString("/untrust")
	}
	switch proxyURL {
	case "":
		b.WriteString("/noproxy")
	case "http://ext.example":
		b.WriteString("/proxyhttp")
	default:
		b.WriteString("/proxyhttps")
	}
	if xfp == "https" {
		b.WriteString("/xfphttps")
	} else {
		b.WriteString("/noxfp")
	}
	return b.String()
}
