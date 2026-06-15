package handlerutils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// unknownClientIP is the sentinel rate-limit key used when no valid client IP
// can be derived (neither the selected X-Forwarded-For entry nor the RemoteAddr
// fallback parses as an IP). Collapsing all malformed/garbage input onto this
// single shared key prevents a client from minting distinct spoofed keys from
// unvalidated input. It is intentionally not a valid IP so it can never collide
// with a real per-IP key.
const unknownClientIP = "unknown"

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

// externalBaseURLKey is the context key under which the resolved, authoritative
// external base URL (H3, part A) is stored. When present and non-empty it is the
// highest-precedence source for GetBaseURL / RequestIsHTTPS, overriding all
// client-supplied forwarded headers regardless of the trust policy.
type externalBaseURLKeyType struct{}

var externalBaseURLKey = externalBaseURLKeyType{}

// WithExternalBaseURL returns a copy of ctx carrying the authoritative external
// base URL. An empty string is treated as "unset" (no override). Callers must
// pass a normalized, validated value (see types.Config.ValidateExternalBaseURL /
// NormalizedExternalBaseURL).
func WithExternalBaseURL(ctx context.Context, baseURL string) context.Context {
	return context.WithValue(ctx, externalBaseURLKey, baseURL)
}

// externalBaseURLFromContext returns the authoritative external base URL and
// whether one is set (non-empty). When ABSENT or empty it returns ("", false)
// so behavior falls back to the trust-gated forwarded-header logic.
func externalBaseURLFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(externalBaseURLKey).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// xffTrustedHopCountKey is the context key under which the configured number of
// trusted proxy hops (H3, part B) is stored. It governs which X-Forwarded-For
// entry GetClientIP uses for the per-IP rate-limit key.
type xffTrustedHopCountKeyType struct{}

var xffTrustedHopCountKey = xffTrustedHopCountKeyType{}

// WithXFFTrustedHopCount returns a copy of ctx carrying the number of trusted
// proxy hops in front of this server.
func WithXFFTrustedHopCount(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, xffTrustedHopCountKey, n)
}

// xffTrustedHopCountFromContext returns the configured trusted-hop count. When
// ABSENT it returns 0 (the secure default: do not trust any XFF entry for the
// rate-limit key).
func xffTrustedHopCountFromContext(ctx context.Context) int {
	n, ok := ctx.Value(xffTrustedHopCountKey).(int)
	if !ok {
		return 0
	}
	return n
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
	// An authoritative external base URL (H3) is the highest precedence: its
	// scheme decides https-ness so the cookie Secure flag matches GetBaseURL,
	// regardless of the trust policy or forwarded headers.
	if base, ok := externalBaseURLFromContext(r.Context()); ok {
		return strings.HasPrefix(base, "https://")
	}
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

// GetClientIP extracts the client IP used as the per-IP rate-limit key for
// /authorize, /token, /register. It MUST be robust against a client spoofing
// X-Forwarded-For to rotate the key, so it honors both the trust-forwarded
// policy (see WithTrustForwarded) and the configured number of trusted proxy
// hops (see WithXFFTrustedHopCount).
//
// Precedence:
//
//  1. trust disabled => ignore all forwarded headers; use RemoteAddr (host).
//  2. trust enabled, N = trusted hops > 0 => the X-Forwarded-For chain is
//     appended left-to-right, so the RIGHTMOST entries are added by the closest
//     trusted proxies. The real client IP is parts[len(parts)-N]; spoofed
//     client-supplied entries sit to the LEFT and are ignored. If N exceeds the
//     number of XFF entries (or there are none), fall back to RemoteAddr (fail
//     safe).
//  3. trust enabled, N == 0 (default) => do NOT trust any XFF entry; use
//     RemoteAddr, so a single spoofed XFF cannot rotate the key.
//
// X-Real-IP is intentionally NOT used for the key: it is a single
// client-spoofable value with no hop accounting, so trusting it would reopen the
// rotation vector. Operators behind a trusted LB should set N to their hop count
// (1 for a single ALB) to get a correct, non-spoofable per-client key.
func GetClientIP(r *http.Request) string {
	if trustForwardedFromContext(r.Context()) {
		if n := xffTrustedHopCountFromContext(r.Context()); n > 0 {
			// Materialize ALL X-Forwarded-For field lines in order before
			// splitting (HIGH-2): a client can send its own line and a trusted LB
			// can APPEND a separate line, and Header.Get would see only the first
			// (client) line. Joining the values preserves the appended order so
			// the rightmost entry is the closest trusted proxy's contribution.
			if lines := r.Header.Values("X-Forwarded-For"); len(lines) > 0 {
				parts := strings.Split(strings.Join(lines, ","), ",")
				if n <= len(parts) {
					// Parse the selected entry safely (MEDIUM-3). Empty/garbage
					// entries fall through to the RemoteAddr fallback so the key is
					// always a valid IP.
					if ip, ok := parseIPCandidate(parts[len(parts)-n]); ok {
						return ip
					}
				}
				// N exceeds the number of entries, or the selected entry is not a
				// valid IP: fail safe to RemoteAddr.
			}
		}
	}

	// Fall back to RemoteAddr (the secure default and the only source when trust
	// is disabled or no trusted-hop count is configured). Parse it the same safe
	// way so an IPv6 RemoteAddr ("[::1]:5555" / bare "::1") is not mangled.
	if ip, ok := parseIPCandidate(r.RemoteAddr); ok {
		return ip
	}
	// No valid IP could be derived from any source. Return the fixed sentinel
	// rather than the raw, unvalidated RemoteAddr so malformed/garbage input
	// collapses to one shared key and cannot be used to mint distinct spoofed
	// keys.
	return unknownClientIP
}

// parseIPCandidate normalizes a single client-IP candidate (an X-Forwarded-For
// entry or RemoteAddr) into a valid IP string for use as the rate-limit key. It
// trims surrounding space, strips an optional ":port" (or "[ipv6]:port") with
// net.SplitHostPort, falls back to the raw value when there is no port, and
// validates the result with netip.ParseAddr. It returns ("", false) when the
// candidate is empty or not a parseable IP, so callers can fail safe. Unlike a
// naive LastIndex(":") port strip, this handles IPv6 (bracketed host:port and
// bare addresses) correctly.
func parseIPCandidate(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	return addr.String(), true
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
	// An authoritative external base URL (H3) overrides everything: return it
	// verbatim and ignore X-Mcp-Oauth-Proxy-URL / X-Forwarded-Proto / r.Host,
	// regardless of the trust policy.
	if base, ok := externalBaseURLFromContext(r.Context()); ok {
		return base
	}

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
