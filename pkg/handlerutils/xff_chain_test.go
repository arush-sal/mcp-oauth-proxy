package handlerutils

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTrustedXFFChain: the chain forwarded upstream is the hop-count-selected
// client IP through the rightmost entry (the same selection GetClientIP uses),
// normalized, or nil (fail closed) whenever no entry is trusted or any entry in
// that suffix is not a valid IP.
func TestTrustedXFFChain(t *testing.T) {
	cases := []struct {
		name  string
		trust bool
		hops  int
		lines []string
		want  []string
	}{
		{name: "untrusted", trust: false, hops: 1, lines: []string{"192.0.2.1, 198.51.100.5"}},
		{name: "zero hops", trust: true, hops: 0, lines: []string{"192.0.2.1, 198.51.100.5"}},
		{name: "no header", trust: true, hops: 1},
		{name: "one hop drops spoofed left", trust: true, hops: 1, lines: []string{"192.0.2.1, 198.51.100.5"}, want: []string{"198.51.100.5"}},
		{name: "two hops", trust: true, hops: 2, lines: []string{"192.0.2.1, 198.51.100.5, 203.0.113.10"}, want: []string{"198.51.100.5", "203.0.113.10"}},
		{name: "duplicate fields joined in order", trust: true, hops: 2, lines: []string{"192.0.2.1, 198.51.100.5", "203.0.113.10"}, want: []string{"198.51.100.5", "203.0.113.10"}},
		{name: "normalizes port and ipv6", trust: true, hops: 2, lines: []string{"198.51.100.5:1234, [2001:db8::1]:443"}, want: []string{"198.51.100.5", "2001:db8::1"}},
		{name: "shorter than hop count", trust: true, hops: 3, lines: []string{"198.51.100.5, 203.0.113.10"}},
		{name: "malformed selected", trust: true, hops: 2, lines: []string{"198.51.100.5, not-an-ip, 203.0.113.10"}},
		{name: "malformed right of selected", trust: true, hops: 2, lines: []string{"198.51.100.5, 203.0.113.10, garbage"}},
		{name: "empty entry", trust: true, hops: 1, lines: []string{"198.51.100.5, "}},
		{name: "malformed left of selected is ignored", trust: true, hops: 1, lines: []string{"garbage, 198.51.100.5"}, want: []string{"198.51.100.5"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://internal.example/path", nil)
			req.RemoteAddr = "10.0.0.1:5555"
			for _, l := range tc.lines {
				req.Header.Add("X-Forwarded-For", l)
			}
			ctx := WithTrustForwarded(req.Context(), tc.trust)
			req = req.WithContext(WithXFFTrustedHopCount(ctx, tc.hops))

			assert.Equal(t, tc.want, TrustedXFFChain(req))
		})
	}
}
