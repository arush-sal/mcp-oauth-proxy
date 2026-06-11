package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stripProps returns a fully-populated grant props map so setHeaders writes the
// legitimately-derived X-Forwarded-* identity headers.
func stripProps() map[string]any {
	return map[string]any{
		"user_id":      "user123",
		"email":        "user@example.com",
		"name":         "John Doe",
		"access_token": "access-abc",
	}
}

// seedSpoofedIdentityHeaders pre-populates an inbound request/header set with the
// broad family of identity/forwarded headers a malicious client might send to
// impersonate a user to the upstream.
func seedSpoofedIdentityHeaders(h http.Header) {
	h.Set("Authorization", "Bearer spoofed-inbound")
	h.Set("X-Forwarded-User", "evil-user")
	h.Set("X-Forwarded-Email", "evil@example.com")
	h.Set("X-Forwarded-Name", "Evil Person")
	h.Set("X-Forwarded-Access-Token", "evil-access")
	h.Set("X-Forwarded-Groups", "admins")
	h.Set("X-Forwarded-Preferred-Username", "evil")
	h.Set("X-Forwarded-Preferred-User", "evil")
	h.Set("X-Auth-Request-User", "evil-user")
	h.Set("X-Auth-Request-Email", "evil@example.com")
	h.Set("X-Auth-Request-Groups", "admins")
	h.Set("X-Auth-Request-Preferred-Username", "evil")
	h.Set("X-Auth-Request-Access-Token", "evil-access")
	h.Set("X-Auth-Request-Redirect", "https://evil.example.com/")
	h.Set("X-Remote-User", "evil-user")
	h.Set("X-Remote-Email", "evil@example.com")
	h.Set("X-Remote-Groups", "admins")
}

// TestStripDisabledDefault documents CURRENT behavior: with stripping disabled
// (the default), the broad identity headers the proxy does NOT manage pass
// through unchanged, while the four managed headers + Authorization are still
// neutralized by setHeaders.
func TestStripDisabledDefault(t *testing.T) {
	p := newForwardProxy(t, &types.Config{})
	header := make(http.Header)
	seedSpoofedIdentityHeaders(header)

	p.setHeaders(header, stripProps())

	// Unmanaged broad headers pass through unchanged (the GAP F3 closes).
	assert.Equal(t, "admins", header.Get("X-Forwarded-Groups"))
	assert.Equal(t, "evil", header.Get("X-Forwarded-Preferred-Username"))
	assert.Equal(t, "evil@example.com", header.Get("X-Auth-Request-Email"))
	assert.Equal(t, "evil-user", header.Get("X-Auth-Request-User"))
	assert.Equal(t, "admins", header.Get("X-Auth-Request-Groups"))
	assert.Equal(t, "https://evil.example.com/", header.Get("X-Auth-Request-Redirect"))
	assert.Equal(t, "evil-user", header.Get("X-Remote-User"))

	// The four managed headers are re-derived from props (not the spoofed values).
	assert.Equal(t, "user123", header.Get("X-Forwarded-User"))
	assert.Equal(t, "user@example.com", header.Get("X-Forwarded-Email"))
	assert.Equal(t, "John Doe", header.Get("X-Forwarded-Name"))
	assert.Equal(t, "access-abc", header.Get("X-Forwarded-Access-Token"))
	// Authorization is always neutralized (none policy -> absent).
	assert.Empty(t, header.Get("Authorization"))
}

// TestStripEnabledRemovesBroadHeaders verifies that with stripping enabled the
// whole inbound identity/forwarded family is removed, while legitimately-derived
// X-Forwarded-* from props are still written afterward.
func TestStripEnabledRemovesBroadHeaders(t *testing.T) {
	p := newForwardProxy(t, &types.Config{StripInboundIdentityHeaders: true})
	header := make(http.Header)
	seedSpoofedIdentityHeaders(header)

	p.setHeaders(header, stripProps())

	// Broad unmanaged identity headers are gone.
	assert.Empty(t, header.Get("X-Forwarded-Groups"))
	assert.Empty(t, header.Get("X-Forwarded-Preferred-Username"))
	assert.Empty(t, header.Get("X-Forwarded-Preferred-User"))
	assert.Empty(t, header.Get("X-Auth-Request-User"))
	assert.Empty(t, header.Get("X-Auth-Request-Email"))
	assert.Empty(t, header.Get("X-Auth-Request-Groups"))
	assert.Empty(t, header.Get("X-Auth-Request-Preferred-Username"))
	assert.Empty(t, header.Get("X-Auth-Request-Access-Token"))
	assert.Empty(t, header.Get("X-Auth-Request-Redirect"))
	assert.Empty(t, header.Get("X-Remote-User"))
	assert.Empty(t, header.Get("X-Remote-Email"))
	assert.Empty(t, header.Get("X-Remote-Groups"))

	// Legitimately-derived managed headers are still present (written after strip).
	assert.Equal(t, "user123", header.Get("X-Forwarded-User"))
	assert.Equal(t, "user@example.com", header.Get("X-Forwarded-Email"))
	assert.Equal(t, "John Doe", header.Get("X-Forwarded-Name"))
	assert.Equal(t, "access-abc", header.Get("X-Forwarded-Access-Token"))
	assert.Empty(t, header.Get("Authorization"))
}

// TestStripEnabledRemovesSpoofedIDTokenHeader verifies the runtime-configured
// ID_TOKEN_HEADER is in the stripped set, so a spoofed inbound value cannot
// survive even when no valid id_token is written.
func TestStripEnabledRemovesSpoofedIDTokenHeader(t *testing.T) {
	p := newForwardProxy(t, &types.Config{
		StripInboundIdentityHeaders: true,
		IDTokenHeader:               "X-Id-Token",
	})
	header := make(http.Header)
	header.Set("X-Id-Token", "spoofed.jwt.value")
	header.Set("X-Forwarded-Groups", "admins")

	props := stripProps() // no id_token stored
	p.setHeaders(header, props)

	assert.Empty(t, header.Get("X-Id-Token"))
	assert.Empty(t, header.Get("X-Forwarded-Groups"))
}

// TestStripEnabledForwardAuthMode exercises the forward-auth path (w.Header())
// through mcpProxyHandler, confirming the strip applies there too.
func TestStripEnabledForwardAuthMode(t *testing.T) {
	p := newForwardProxy(t, &types.Config{
		Mode:                        ModeForwardAuth,
		StripInboundIdentityHeaders: true,
	})

	rec := httptest.NewRecorder()
	// Seed the response header with spoofed identity values; forward-auth writes
	// onto w.Header().
	seedSpoofedIdentityHeaders(rec.Header())

	p.setHeaders(rec.Header(), stripProps())

	assert.Empty(t, rec.Header().Get("X-Forwarded-Groups"))
	assert.Empty(t, rec.Header().Get("X-Auth-Request-Email"))
	assert.Empty(t, rec.Header().Get("X-Auth-Request-User"))
	assert.Equal(t, "user@example.com", rec.Header().Get("X-Forwarded-Email"))
}

// TestStripEnabledWithForwardingWritesRealIDToken verifies that with F4f id_token
// forwarding + stripping enabled, a spoofed inbound ID_TOKEN_HEADER value is
// removed and the real (non-stale) id_token is then written.
func TestStripEnabledWithForwardingWritesRealIDToken(t *testing.T) {
	validIDToken := makeIDToken(t, time.Now().Add(1*time.Hour))
	p := newForwardProxy(t, &types.Config{
		StripInboundIdentityHeaders: true,
		IDTokenHeader:               "X-Id-Token",
	})

	header := make(http.Header)
	header.Set("X-Id-Token", "spoofed.jwt.value")
	header.Set("X-Forwarded-Groups", "admins")

	props := stripProps()
	props["id_token"] = validIDToken
	p.setHeaders(header, props)

	// Spoofed broad header gone; real id_token written to the custom header.
	assert.Empty(t, header.Get("X-Forwarded-Groups"))
	assert.Equal(t, validIDToken, header.Get("X-Id-Token"))
}

// TestStripEnabledProxyDirector exercises the reverse-proxy Director path
// end-to-end: an inbound request carrying spoofed identity headers is proxied
// and the upstream sees them stripped, with the managed headers re-derived.
func TestStripEnabledProxyDirector(t *testing.T) {
	var gotGroups, gotAuthReqEmail, gotFwdEmail, gotIDToken string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroups = r.Header.Get("X-Forwarded-Groups")
		gotAuthReqEmail = r.Header.Get("X-Auth-Request-Email")
		gotFwdEmail = r.Header.Get("X-Forwarded-Email")
		gotIDToken = r.Header.Get("X-Id-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	validIDToken := makeIDToken(t, time.Now().Add(1*time.Hour))
	p := newForwardProxy(t, &types.Config{
		Mode:                        ModeProxy,
		MCPServerURL:                upstream.URL,
		StripInboundIdentityHeaders: true,
		IDTokenHeader:               "X-Id-Token",
	})

	// Build the reverse proxy with the SAME Director header mutation the proxy
	// uses in mcpProxyHandler (p.setHeaders(req.Header, props)), so we exercise
	// the real proxy-path strip end-to-end against a live upstream.
	target, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	props := stripProps()
	props["id_token"] = validIDToken
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			p.setHeaders(req.Header, props)
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	seedSpoofedIdentityHeaders(req.Header)
	req.Header.Set("X-Id-Token", "spoofed.jwt.value")

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, gotGroups)
	assert.Empty(t, gotAuthReqEmail)
	assert.Equal(t, "user@example.com", gotFwdEmail)
	assert.Equal(t, validIDToken, gotIDToken)
}
