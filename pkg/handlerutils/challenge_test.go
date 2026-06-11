package handlerutils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteBearerChallenge_HeaderAndBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/mcp/foo", nil)
	rec := httptest.NewRecorder()

	WriteBearerChallenge(rec, req, "Token expired and refresh failed")

	require.Equal(t, http.StatusUnauthorized, rec.Code)

	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer error="invalid_token", error_description="Token expired and refresh failed", resource_metadata="https://proxy.example.com/.well-known/oauth-protected-resource/mcp/foo"`
	assert.Equal(t, want, got)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_token", body["error"])
	assert.Equal(t, "Token expired and refresh failed", body["error_description"])
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestWriteBearerChallenge_EscapesQuotesInHeader(t *testing.T) {
	// A message containing a double quote must not break out of the quoted
	// error_description value in the WWW-Authenticate header (header injection).
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/mcp", nil)
	rec := httptest.NewRecorder()

	WriteBearerChallenge(rec, req, `bad"; injected="x`)

	got := rec.Header().Get("WWW-Authenticate")
	// The raw, unescaped sequence must not appear verbatim in the header.
	assert.NotContains(t, got, `bad"; injected="x`)
	// It must remain a single well-formed Bearer challenge with the three params.
	assert.True(t, strings.HasPrefix(got, `Bearer error="invalid_token"`), got)
	assert.Contains(t, got, `resource_metadata="https://proxy.example.com/.well-known/oauth-protected-resource/mcp"`)
	// No raw CR/LF can be injected either.
	assert.NotContains(t, got, "\r")
	assert.NotContains(t, got, "\n")

	// The JSON body still carries the (unescaped) human-readable message.
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_token", body["error"])
}

func TestWriteBearerChallenge_PathCannotBreakOutOfResourceMetadata(t *testing.T) {
	// r.URL.Path is percent-DECODED, so a crafted request path containing %22
	// would yield a literal double quote in the path. It must not break out of
	// the resource_metadata quoted-string and forge extra auth-params.
	req := httptest.NewRequest(http.MethodGet, `https://proxy.example.com/mcp%22,%20error=%22injected`, nil)
	rec := httptest.NewRecorder()

	WriteBearerChallenge(rec, req, "Token expired")

	got := rec.Header().Get("WWW-Authenticate")
	// Still exactly one well-formed Bearer challenge, no forged params.
	assert.True(t, strings.HasPrefix(got, `Bearer error="invalid_token", error_description="Token expired", resource_metadata="`), got)
	// No raw breakout quote: the only unescaped quotes are the param delimiters.
	// The decoded path quote must appear escaped (\") inside resource_metadata,
	// never as a bare quote that closes the value early.
	assert.NotContains(t, got, `error="injected`)
	assert.NotContains(t, got, "\r")
	assert.NotContains(t, got, "\n")
}

func TestWriteBearerChallenge_HostCannotBreakOutOfResourceMetadata(t *testing.T) {
	// GetBaseURL falls back to r.Host, which is the client-supplied HTTP Host
	// header. Unlike the request path, r.Host is NOT percent-encoded by
	// EscapedPath, so a malicious Host carrying a LITERAL double quote (and
	// backslash) flows raw into resource_metadata. Only sanitizeHeaderQuotedValue
	// stands between that raw '"' and a forged auth-param. This is the realistic
	// literal-quote vector that %22-in-path cannot exercise.
	req := httptest.NewRequest(http.MethodGet, "https://example.com/mcp", nil)
	// Trust-forwarded is the default (no context set) and no X-Mcp-Oauth-Proxy-URL
	// header, so GetBaseURL derives the host from r.Host below.
	req.Host = `ev\il"x, error="injected`

	rec := httptest.NewRecorder()
	WriteBearerChallenge(rec, req, "Token expired")

	got := rec.Header().Get("WWW-Authenticate")

	// The raw Host string must not appear verbatim: the literal '"' from Host must
	// be backslash-escaped so it cannot close the resource_metadata quoted-string.
	assert.NotContains(t, got, `ev\il"x, error="injected`,
		"raw Host with a literal quote must not appear unescaped in the header")
	assert.Contains(t, got, `ev\\il\"x, error=\"injected`,
		"the literal backslash and quotes from Host must be backslash-escaped")
	// No forged top-level auth-param could be created from the Host injection.
	assert.NotContains(t, got, `, error="injected"`)

	// Still exactly one well-formed Bearer challenge with the three expected
	// params, in order, and nothing else: parse the unescaped quoted-strings out.
	assert.True(t, strings.HasPrefix(got, `Bearer error="invalid_token", error_description="Token expired", resource_metadata="`), got)
	assert.True(t, strings.HasSuffix(got, `"`), got)
	assert.Equal(t, 6, countUnescapedParamQuotes(got),
		"header must contain exactly three quoted auth-params (six delimiter quotes, no forged extras)")

	// No header injection.
	assert.NotContains(t, got, "\r")
	assert.NotContains(t, got, "\n")
}

// countUnescapedParamQuotes counts the double quotes that actually delimit
// quoted-string values, i.e. quotes NOT preceded by a backslash. A well-formed
// challenge with three params has exactly six such quotes.
func countUnescapedParamQuotes(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		// Count preceding backslashes; an even count means the quote is a real
		// (unescaped) delimiter.
		bs := 0
		for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
			bs++
		}
		if bs%2 == 0 {
			n++
		}
	}
	return n
}

func TestSanitizeHeaderQuotedValue(t *testing.T) {
	// Direct in-package unit test: a raw quote and backslash are escaped, and an
	// ASCII control char is stripped, so the result is safe to embed in a
	// double-quoted RFC 7235 auth-param value.
	got := sanitizeHeaderQuotedValue("a\"b\\c\r\nd\x00e")
	assert.Equal(t, `a\"b\\cde`, got)
	assert.NotContains(t, got, "\r")
	assert.NotContains(t, got, "\n")
	assert.NotContains(t, got, "\x00")
}

func TestWriteBearerChallenge_StripsControlChars(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/mcp", nil)
	rec := httptest.NewRecorder()

	WriteBearerChallenge(rec, req, "line1\r\nInjected-Header: evil")

	got := rec.Header().Get("WWW-Authenticate")
	// CR/LF stripped: the remaining text stays inside the single quoted
	// error_description value, so it is one well-formed header line and cannot
	// forge a separate "Injected-Header" response header.
	assert.NotContains(t, got, "\r")
	assert.NotContains(t, got, "\n")
	require.Empty(t, rec.Header().Values("Injected-Header"), "must not forge a separate header")
}
