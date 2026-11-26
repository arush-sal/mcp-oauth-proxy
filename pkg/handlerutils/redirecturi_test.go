package handlerutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRedirectURIMatches covers the loopback any-port rule (RFC 8252 section
// 7.3). The default is an exact string match; only for an http loopback
// registered URI is the port ignored, and only the port -- scheme, host, path
// and query must still match exactly.
func TestRedirectURIMatches(t *testing.T) {
	tests := []struct {
		name       string
		registered []string
		requested  string
		want       bool
	}{
		{
			name:       "exact match",
			registered: []string{"http://localhost:40001/callback"},
			requested:  "http://localhost:40001/callback",
			want:       true,
		},
		{
			name:       "http loopback different port passes",
			registered: []string{"http://localhost:40001/callback"},
			requested:  "http://localhost:40002/callback",
			want:       true,
		},
		{
			name:       "http 127.0.0.1 different port passes",
			registered: []string{"http://127.0.0.1:40001/callback"},
			requested:  "http://127.0.0.1:52345/callback",
			want:       true,
		},
		{
			name:       "http ipv6 loopback different port passes",
			registered: []string{"http://[::1]:40001/callback"},
			requested:  "http://[::1]:9999/callback",
			want:       true,
		},
		{
			name:       "loopback registered without port, requested with port passes",
			registered: []string{"http://localhost/callback"},
			requested:  "http://localhost:40002/callback",
			want:       true,
		},
		{
			name:       "http loopback different path fails",
			registered: []string{"http://localhost:40001/callback"},
			requested:  "http://localhost:40002/evil",
			want:       false,
		},
		{
			name:       "http loopback different host fails",
			registered: []string{"http://127.0.0.1:40001/callback"},
			requested:  "http://localhost:40001/callback",
			want:       false,
		},
		{
			name:       "http loopback different query fails",
			registered: []string{"http://localhost:40001/callback?a=1"},
			requested:  "http://localhost:40002/callback?a=2",
			want:       false,
		},
		{
			name:       "http loopback same query different port passes",
			registered: []string{"http://localhost:40001/callback?a=1"},
			requested:  "http://localhost:40002/callback?a=1",
			want:       true,
		},
		{
			name:       "scheme downgrade http registered https requested fails",
			registered: []string{"http://localhost:40001/callback"},
			requested:  "https://localhost:40002/callback",
			want:       false,
		},
		{
			name:       "https loopback different port fails (RFC 8252 covers http only)",
			registered: []string{"https://localhost:40001/callback"},
			requested:  "https://localhost:40002/callback",
			want:       false,
		},
		{
			name:       "https loopback exact passes",
			registered: []string{"https://localhost:40001/callback"},
			requested:  "https://localhost:40001/callback",
			want:       true,
		},
		{
			name:       "non-loopback http different port fails",
			registered: []string{"http://example.com:40001/callback"},
			requested:  "http://example.com:40002/callback",
			want:       false,
		},
		{
			name:       "https non-loopback exact passes",
			registered: []string{"https://app.example/cb"},
			requested:  "https://app.example/cb",
			want:       true,
		},
		{
			name:       "https non-loopback mismatch fails",
			registered: []string{"https://app.example/cb"},
			requested:  "https://evil.example/cb",
			want:       false,
		},
		{
			name:       "matches when one of several registered is loopback",
			registered: []string{"https://app.example/cb", "http://localhost:40001/callback"},
			requested:  "http://localhost:50000/callback",
			want:       true,
		},
		{
			name:       "empty requested fails",
			registered: []string{"http://localhost:40001/callback"},
			requested:  "",
			want:       false,
		},
		{
			name:       "embedded credentials rejected",
			registered: []string{"http://127.0.0.1:40001/callback"},
			requested:  "http://evil@127.0.0.1:40002/callback",
			want:       false,
		},
		{
			name:       "fragment rejected",
			registered: []string{"http://127.0.0.1:40001/callback"},
			requested:  "http://127.0.0.1:40002/callback#frag",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedirectURIMatches(tt.registered, tt.requested); got != tt.want {
				t.Fatalf("RedirectURIMatches(%q, %q) = %v, want %v", tt.registered, tt.requested, got, tt.want)
			}
		})
	}
}

func TestParseHTTPSRedirectHosts(t *testing.T) {
	ok := []string{"none", "NONE", "", "  ", ",,", "claude.ai", "claude.ai, chatgpt.com ,", "localhost", "a-b.example.com"}
	for _, in := range ok {
		_, err := ParseHTTPSRedirectHosts(in)
		assert.NoError(t, err, "input %q", in)
	}
	bad := []string{
		"https://claude.ai", "claude.ai/path", "*.claude.ai", "*", "claude.ai:443",
		"[::1]", "user@claude.ai", "none,claude.ai", "claude.ai,none", "bad host",
		".claude.ai", "claude.ai.", "-a.example", "claude.ai?x", "claude.ai#x",
	}
	for _, in := range bad {
		_, err := ParseHTTPSRedirectHosts(in)
		assert.Error(t, err, "input %q", in)
	}
}

func TestHTTPSRedirectHostsAllowsRedirectURI(t *testing.T) {
	var unset *HTTPSRedirectHosts
	assert.True(t, unset.AllowsRedirectURI("https://anything.example/cb"))

	p, err := ParseHTTPSRedirectHosts("claude.ai")
	assert.NoError(t, err)
	assert.True(t, p.AllowsRedirectURI("https://claude.ai/cb"))
	assert.True(t, p.AllowsRedirectURI("HTTPS://CLAUDE.AI:8443/cb"))
	assert.False(t, p.AllowsRedirectURI("https://evil.claude.ai/cb"))
	assert.False(t, p.AllowsRedirectURI("https:///cb"))
	assert.True(t, p.AllowsRedirectURI("http://localhost:1/cb"))
	assert.True(t, p.AllowsRedirectURI("cursor://x/cb"))
}

func TestParseHTTPSRedirectHostsIDNRequiresPunycode(t *testing.T) {
	_, err := ParseHTTPSRedirectHosts("b\u00fccher.example")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "punycode")
	}
	_, err = ParseHTTPSRedirectHosts("xn--bcher-kva.example")
	assert.NoError(t, err)
}
