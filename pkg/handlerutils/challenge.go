package handlerutils

import (
	"fmt"
	"net/http"
	"strings"
)

// sanitizeHeaderQuotedValue makes an arbitrary message safe to embed inside a
// double-quoted RFC 7235 auth-param value in a response header. It:
//   - drops CR/LF (and other control characters) so the message can never inject
//     a new header line, and
//   - backslash-escapes embedded backslashes and double quotes so the message
//     cannot terminate the quoted-string early and forge extra auth-params.
func sanitizeHeaderQuotedValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\\' || r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			// Strip ASCII control characters (covers CR, LF, NUL, etc.).
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// WriteBearerChallenge writes the standard agent re-auth challenge: a 401 with a
// WWW-Authenticate Bearer challenge that points the client at this resource's
// protected-resource metadata so it can re-run discovery / PKCE, plus a JSON
// body describing the error.
//
// The header format is, byte-for-byte:
//
//	Bearer error="invalid_token", error_description="<message>", resource_metadata="<baseURL>/.well-known/oauth-protected-resource<path>"
//
// where <message> is sanitized for safe embedding in the quoted-string (CR/LF
// stripped, backslashes and quotes escaped) so it can never inject extra headers
// or auth-params. The JSON body carries the original (unescaped) human-readable
// message, which net/http JSON-encodes safely.
func WriteBearerChallenge(w http.ResponseWriter, r *http.Request, message string) {
	// Use EscapedPath so the path keeps valid URL percent-encoding (a literal
	// '"' in the request path stays %22), then sanitize the whole metadata value
	// for quoted-string embedding so a crafted path cannot break out of the
	// resource_metadata quoted-string and forge extra auth-params.
	resourceMetadata := fmt.Sprintf("%s/.well-known/oauth-protected-resource%s", GetBaseURL(r), r.URL.EscapedPath())

	w.Header().Set(
		"WWW-Authenticate",
		fmt.Sprintf(
			`Bearer error="invalid_token", error_description="%s", resource_metadata="%s"`,
			sanitizeHeaderQuotedValue(message),
			sanitizeHeaderQuotedValue(resourceMetadata),
		),
	)

	JSON(w, http.StatusUnauthorized, map[string]string{
		"error":             "invalid_token",
		"error_description": message,
	})
}
