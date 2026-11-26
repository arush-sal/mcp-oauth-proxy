package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/validate"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// outboundRecord is what the upstream observed for one proxied request.
type outboundRecord struct {
	host         string
	upstreamHost string
	requestURI   string
	path         string
	header       http.Header
}

// proxyThroughHandler runs a real client -> frontend server -> mcpProxyHandler
// (proxy mode) -> recording upstream round trip, so the inbound request has the
// same shape as in production (empty URL.Scheme, real RemoteAddr, raw
// RequestURI). The upstream answers with a Location pointing at itself to
// exercise the ModifyResponse rewrite.
func proxyThroughHandler(t *testing.T, cfg *types.Config, props map[string]any, build func(*http.Request)) (outboundRecord, *http.Response) {
	t.Helper()

	var got outboundRecord
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = outboundRecord{host: r.Host, requestURI: r.RequestURI, path: r.URL.Path, header: r.Header.Clone()}
		w.Header().Set("Location", "http://"+r.Host+"/next?step=2")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	cfg.Mode = ModeProxy
	cfg.MCPServerURL = upstream.URL
	p := newForwardProxy(t, cfg)

	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ti := &tokens.TokenInfo{UserID: "user123", GrantID: "grant-1", Props: props}
		p.mcpProxyHandler(w, r.WithContext(validate.ContextWithTokenInfo(r.Context(), ti)), nil)
	}))
	t.Cleanup(frontend.Close)

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/mcp/a%2Fb/c?x=1&y=two%20words&x=2&bad=1;semi=2&esc=%zz", nil)
	require.NoError(t, err)
	req.Host = "proxy.example.com"
	if build != nil {
		build(req)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	got.upstreamHost = target.Host
	return got, resp
}

// TestProxyOutboundRequestPinned pins the exact outbound request the upstream
// receives in proxy mode (default config: stripping disabled, no token
// forwarding) so the ReverseProxy hook can be changed without altering it.
func TestProxyOutboundRequestPinned(t *testing.T) {
	got, resp := proxyThroughHandler(t, &types.Config{}, stripProps(), func(r *http.Request) {
		seedSpoofedIdentityHeaders(r.Header)
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Forwarded-Host", "evil.example.com")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Uri", "/client/uri")
		r.Header.Set("Forwarded", "for=198.51.100.1")
		r.Header.Set("X-Custom", "kept")
		r.Header.Set("User-Agent", "mcp-agent/1.0")
		r.Header.Set("Connection", "X-Hop")
		r.Header.Set("X-Hop", "dropped")
	})

	// URL: upstream host, inbound path and raw query verbatim (unparsable query
	// params are kept).
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, got.upstreamHost, got.host)
	assert.Equal(t, "/mcp/a%2Fb/c?x=1&y=two%20words&x=2&bad=1;semi=2&esc=%zz", got.requestURI)
	assert.Equal(t, "/mcp/a/b/c", got.path)

	// Forwarded headers: XFF keeps the client's chain and appends the peer IP;
	// X-Forwarded-Host is the inbound Host; X-Forwarded-Proto is the inbound
	// request URL scheme (empty for server requests); Forwarded and
	// X-Forwarded-Uri pass through.
	assert.Equal(t, []string{"203.0.113.9, 127.0.0.1"}, got.header["X-Forwarded-For"])
	assert.Equal(t, []string{"proxy.example.com"}, got.header["X-Forwarded-Host"])
	assert.Equal(t, []string{""}, got.header["X-Forwarded-Proto"])
	assert.Equal(t, []string{"for=198.51.100.1"}, got.header["Forwarded"])
	assert.Equal(t, "/client/uri", got.header.Get("X-Forwarded-Uri"))

	// Proxy-managed identity headers are re-derived from the grant, never the
	// spoofed inbound values; inbound Authorization is dropped (policy none).
	assert.Equal(t, []string{"user123"}, got.header["X-Forwarded-User"])
	assert.Equal(t, []string{"user@example.com"}, got.header["X-Forwarded-Email"])
	assert.Equal(t, []string{"John Doe"}, got.header["X-Forwarded-Name"])
	assert.Equal(t, []string{"access-abc"}, got.header["X-Forwarded-Access-Token"])
	assert.NotContains(t, got.header, "Authorization")

	// Stripping disabled: unmanaged identity headers pass through unchanged.
	assert.Equal(t, "admins", got.header.Get("X-Forwarded-Groups"))
	assert.Equal(t, "evil-user", got.header.Get("X-Remote-User"))

	// Ordinary headers pass through; hop-by-hop headers are removed.
	assert.Equal(t, "kept", got.header.Get("X-Custom"))
	assert.Equal(t, "mcp-agent/1.0", got.header.Get("User-Agent"))
	assert.NotContains(t, got.header, "X-Hop")
	assert.NotContains(t, got.header, "Connection")

	// ModifyResponse rewrites an upstream-host Location to the proxy host.
	assert.Equal(t, "http://proxy.example.com/next?step=2", resp.Header.Get("Location"))
}

// TestProxyOutboundNoClientForwardedHeaders pins that, absent client-supplied
// forwarded headers, XFF is just the peer IP and Forwarded is absent.
func TestProxyOutboundNoClientForwardedHeaders(t *testing.T) {
	got, _ := proxyThroughHandler(t, &types.Config{}, stripProps(), nil)

	assert.Equal(t, []string{"127.0.0.1"}, got.header["X-Forwarded-For"])
	assert.Equal(t, []string{"proxy.example.com"}, got.header["X-Forwarded-Host"])
	assert.Equal(t, []string{""}, got.header["X-Forwarded-Proto"])
	assert.NotContains(t, got.header, "Forwarded")
}

// TestProxyOutboundStripAndForwarding exercises the real proxy path with
// inbound stripping and token forwarding enabled: spoofed identity headers
// (including the configured ID_TOKEN_HEADER) are removed, and the proxy's own
// Authorization / id_token values are written.
func TestProxyOutboundStripAndForwarding(t *testing.T) {
	props := stripProps()
	props["id_token"] = idTokenValue
	props["id_token_exp"] = time.Now().Add(1 * time.Hour).Unix()

	got, _ := proxyThroughHandler(t, &types.Config{
		StripInboundIdentityHeaders: true,
		AuthorizationHeaderToken:    authHeaderTokenAccessToken,
		IDTokenHeader:               "X-Id-Token",
	}, props, func(r *http.Request) {
		seedSpoofedIdentityHeaders(r.Header)
		r.Header.Set("X-Id-Token", "spoofed.jwt.value")
	})

	assert.Empty(t, got.header.Get("X-Forwarded-Groups"))
	assert.Empty(t, got.header.Get("X-Auth-Request-Email"))
	assert.Empty(t, got.header.Get("X-Remote-User"))
	assert.Equal(t, []string{"user@example.com"}, got.header["X-Forwarded-Email"])
	assert.Equal(t, []string{"Bearer access-abc"}, got.header["Authorization"])
	assert.Equal(t, []string{idTokenValue}, got.header["X-Id-Token"])
}

// TestProxyOutboundConnectionCannotDropProxyHeaders: a client naming
// proxy-written headers in its Connection header (RFC 9110 7.6.1) must not be
// able to remove them from the outbound request.
func TestProxyOutboundConnectionCannotDropProxyHeaders(t *testing.T) {
	got, resp := proxyThroughHandler(t, &types.Config{AuthorizationHeaderToken: authHeaderTokenAccessToken}, stripProps(), func(r *http.Request) {
		r.Header.Set("Connection", "X-Forwarded-User, X-Forwarded-Host, Authorization")
	})

	assert.Equal(t, []string{"user123"}, got.header["X-Forwarded-User"])
	assert.Equal(t, []string{"proxy.example.com"}, got.header["X-Forwarded-Host"])
	assert.Equal(t, []string{"Bearer access-abc"}, got.header["Authorization"])
	assert.Equal(t, "http://proxy.example.com/next?step=2", resp.Header.Get("Location"))
}
