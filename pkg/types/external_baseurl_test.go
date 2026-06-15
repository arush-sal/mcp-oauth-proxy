package types

import "testing"

// TestValidateExternalBaseURL verifies startup validation: an unset value is
// allowed, a valid absolute http/https URL with a host is allowed, and a
// malformed value (no scheme, no host, non-http scheme, or trailing path/query)
// is rejected.
func TestValidateExternalBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"Unset", "", false},
		{"ValidHTTPS", "https://canonical.example", false},
		{"ValidHTTP", "http://canonical.example:8080", false},
		{"TrailingSlash", "https://canonical.example/", false},
		{"MissingScheme", "canonical.example", true},
		{"MissingHost", "https://", true},
		{"NonHTTPScheme", "ftp://canonical.example", true},
		{"Garbage", "://noscheme", true},
		{"WithPath", "https://canonical.example/prefix", true},
		{"WithQuery", "https://canonical.example?x=1", true},
		// MEDIUM-4: url.Parse sets ForceQuery (with empty RawQuery) for a bare
		// "?", and embedded credentials must be rejected so the origin can be
		// used verbatim.
		{"ForceQueryEmpty", "https://canonical.example?", true},
		{"EmbeddedCredentials", "https://user:pass@canonical.example", true},
		{"EmbeddedUserOnly", "https://user@canonical.example", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{ExternalBaseURL: tc.in}
			err := c.ValidateExternalBaseURL()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q, got nil", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
		})
	}
}

// TestNormalizedExternalBaseURL verifies the normalized accessor strips a
// trailing slash and returns "" when unset.
func TestNormalizedExternalBaseURL(t *testing.T) {
	cases := map[string]string{
		"":                            "",
		"https://canonical.example":   "https://canonical.example",
		"https://canonical.example/":  "https://canonical.example",
		"http://canonical.example:80": "http://canonical.example:80",
		// HIGH-1: the scheme must be lowercased (url.Parse normalizes it) so the
		// stored value's "https://" prefix is reliable for RequestIsHTTPS; the
		// host case is preserved.
		"HTTPS://Example.com":  "https://Example.com",
		"HtTpS://Example.com/": "https://Example.com",
		"HTTP://Example.com":   "http://Example.com",
	}
	for in, want := range cases {
		c := &Config{ExternalBaseURL: in}
		if got := c.NormalizedExternalBaseURL(); got != want {
			t.Fatalf("NormalizedExternalBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}
