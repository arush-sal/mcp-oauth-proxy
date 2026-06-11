package types

import "testing"

// TestTrustForwardedHeadersEnabled verifies the tri-state resolver: nil and
// &true resolve to true (preserve current trusting behavior); &false resolves
// to false.
func TestTrustForwardedHeadersEnabled(t *testing.T) {
	tr := true
	fa := false

	tests := []struct {
		name string
		ptr  *bool
		want bool
	}{
		{"NilDefaultsToTrue", nil, true},
		{"ExplicitTrue", &tr, true},
		{"ExplicitFalse", &fa, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{TrustForwardedHeaders: tc.ptr}
			if got := c.TrustForwardedHeadersEnabled(); got != tc.want {
				t.Fatalf("TrustForwardedHeadersEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}
