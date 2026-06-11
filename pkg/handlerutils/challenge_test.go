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
