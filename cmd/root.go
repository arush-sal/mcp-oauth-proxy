package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gptscript-ai/cmd"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/proxy"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

// RootCmd represents the base command when called without any subcommands
type RootCmd struct {
	// Database configuration
	DatabaseDSN string `name:"database-dsn" env:"DATABASE_DSN" usage:"Database connection string (PostgreSQL or SQLite file path). If empty, uses SQLite at data/oauth_proxy.db"`

	// OAuth Provider configuration
	OAuthClientID     string `name:"oauth-client-id" env:"OAUTH_CLIENT_ID" usage:"OAuth client ID from your OAuth provider" required:"true"`
	OAuthClientSecret string `name:"oauth-client-secret" env:"OAUTH_CLIENT_SECRET" usage:"OAuth client secret from your OAuth provider" required:"true"`
	OAuthAuthorizeURL string `name:"oauth-authorize-url" env:"OAUTH_AUTHORIZE_URL" usage:"Authorization endpoint URL from your OAuth provider (e.g., https://accounts.google.com)" required:"true"`
	OAuthJWKSURL      string `name:"oauth-jwks-url" env:"OAUTH_JWKS_URL" usage:"JWKS endpoint URL from your OAuth provider (e.g., https://accounts.google.com/.well-known/openid-configuration/jwks)"`
	OAuthIssuerURL    string `name:"oauth-issuer-url" env:"OAUTH_ISSUER_URL" usage:"Expected id_token issuer (iss). Overrides the issuer derived from the authorize URL; required for path-based issuers like Keycloak (https://host/realms/x)"`

	// Authorization / allowlist (oauth2-proxy parity). WARNING: with none of
	// these set, the proxy DENIES ALL authenticated users (fail-closed default).
	AllowedEmails              string `name:"allowed-emails" env:"ALLOWED_EMAILS" usage:"Comma-separated list of allowed email addresses"`
	AllowedEmailsFile          string `name:"allowed-emails-file" env:"ALLOWED_EMAILS_FILE" usage:"Path to a file of allowed emails, one per line (blank lines and lines starting with # are ignored)"`
	AllowedEmailDomains        string `name:"allowed-email-domains" env:"ALLOWED_EMAIL_DOMAINS" usage:"Comma-separated list of allowed email domains. The special value '*' allows ANY authenticated user"`
	AllowedGroups              string `name:"allowed-groups" env:"ALLOWED_GROUPS" usage:"Comma-separated list of allowed groups"`
	GroupsClaim                string `name:"groups-claim" env:"GROUPS_CLAIM" usage:"id_token claim that carries the user's groups" default:"groups"`
	AllowedGoogleHostedDomains string `name:"allowed-google-hosted-domains" env:"ALLOWED_GOOGLE_HOSTED_DOMAINS" usage:"Comma-separated list of allowed Google hosted domains (checked against the 'hd' claim)"`

	// Upstream token forwarding (F4f). Forward the verified id_token (or the
	// access token) to the upstream MCP server. Default: forward nothing.
	AuthorizationHeaderToken string `name:"authorization-header-token" env:"AUTHORIZATION_HEADER_TOKEN" usage:"Which token to place on the upstream Authorization header: 'none' (default), 'access_token', or 'id_token'" default:"none"`
	IDTokenHeader            string `name:"id-token-header" env:"ID_TOKEN_HEADER" usage:"Optional custom header to carry the raw verified id_token (no 'Bearer ' prefix). When empty and forwarding id_token, uses 'Authorization: Bearer <id_token>'"`

	// Inbound header hygiene (F3). Default false preserves current behavior.
	StripInboundIdentityHeaders bool `name:"strip-inbound-identity-headers" env:"STRIP_INBOUND_IDENTITY_HEADERS" usage:"Strip client-supplied identity/forwarded headers (X-Forwarded-*, X-Auth-Request-*, the configured ID_TOKEN_HEADER) from the upstream request so a caller cannot spoof identity. The four proxy-managed X-Forwarded-* headers + Authorization are always neutralized regardless"`

	// Scopes and MCP configuration
	ScopesSupported string `name:"scopes-supported" env:"SCOPES_SUPPORTED" usage:"Comma-separated list of supported OAuth scopes (e.g., 'openid,profile,email')" required:"true"`
	MCPServerURL    string `name:"mcp-server-url" env:"MCP_SERVER_URL" usage:"URL of the MCP server to proxy requests to" required:"true"`

	// Security configuration
	EncryptionKey string `name:"encryption-key" env:"ENCRYPTION_KEY" usage:"Base64-encoded 32-byte AES-256 key for encrypting sensitive data (optional)"`

	// Session & cookie lifetime / security (F5). Defaults reproduce the prior
	// hardcoded behavior exactly.
	CookieExpire   string `name:"cookie-expire" env:"COOKIE_EXPIRE" usage:"Access-token / access-cookie lifetime as a Go duration (e.g. 30m, 1h, 2h)" default:"1h"`
	CookieRefresh  string `name:"cookie-refresh" env:"COOKIE_REFRESH" usage:"Refresh-token / refresh-cookie lifetime AND grant expiry as a Go duration (e.g. 720h)" default:"720h"`
	CookieSecure   string `name:"cookie-secure" env:"COOKIE_SECURE" usage:"Cookie Secure attribute policy: 'auto' (Secure when request is HTTPS), 'true' (always), or 'false' (never)" default:"auto"`
	CookieSameSite string `name:"cookie-samesite" env:"COOKIE_SAMESITE" usage:"Cookie SameSite attribute: 'lax' (default), 'strict', or 'none' ('none' requires COOKIE_SECURE=true)" default:"lax"`

	// Server configuration
	Port        string `name:"port" env:"PORT" usage:"Port to run the server on" default:"8080"`
	Host        string `name:"host" env:"HOST" usage:"Host to bind the server to" default:"localhost"`
	RoutePrefix string `name:"route-prefix" env:"ROUTE_PREFIX" usage:"Optional prefix for all routes (e.g., '/oauth2')"`

	// Health & metrics (F6). Probes are always on at root paths; metrics are
	// off by default. Defaults preserve existing behavior (legacy /health stays).
	HealthPath     string `name:"health-path" env:"HEALTH_PATH" usage:"Liveness probe path (returns 200 unconditionally)" default:"/healthz"`
	ReadyPath      string `name:"ready-path" env:"READY_PATH" usage:"Readiness probe path (200 when the database is reachable, 503 otherwise)" default:"/readyz"`
	EnableMetrics  bool   `name:"enable-metrics" env:"ENABLE_METRICS" usage:"Enable Prometheus metrics endpoint"`
	MetricsPath    string `name:"metrics-path" env:"METRICS_PATH" usage:"Path for the Prometheus metrics endpoint" default:"/metrics"`
	MetricsAddress string `name:"metrics-address" env:"METRICS_ADDRESS" usage:"When set (e.g. ':9090'), serve metrics on a SEPARATE listener at this address instead of the main mux"`

	// Dynamic Client Registration (DCR) toggle (F2). Default true preserves
	// today's behavior. When false, /register returns 403 and the
	// authorization-server metadata omits the registration endpoint; existing
	// stored clients keep working.
	EnableDynamicClientRegistration bool `name:"enable-dynamic-client-registration" env:"ENABLE_DYNAMIC_CLIENT_REGISTRATION" usage:"Allow clients to self-register via the /register endpoint (RFC 7591). When false, /register returns 403 and metadata omits the registration endpoint; existing clients keep working" default:"true"`

	// Trust forwarded headers (follow-up #2). Default true preserves today's
	// behavior (honors X-Mcp-Oauth-Proxy-URL / X-Forwarded-Proto). When false,
	// the proxy does NOT trust those forwarded headers; the external base URL
	// (which feeds redirect URIs, metadata, and the WWW-Authenticate
	// resource_metadata) is derived from the connection (TLS) and the request
	// Host header. Set false when the proxy is NOT behind a trusted reverse
	// proxy. Note: the Host header itself should be constrained by a fronting
	// reverse proxy / allowed-host config at the infrastructure layer.
	TrustForwardedHeaders bool `name:"trust-forwarded-headers" env:"TRUST_FORWARDED_HEADERS" usage:"Trust client-supplied forwarded headers (X-Mcp-Oauth-Proxy-URL, X-Forwarded-Proto) when deriving the external base URL. When false, those forwarded headers are not trusted and the base URL is derived from the connection (TLS) and the request Host header; constrain the Host header at the infrastructure layer (fronting reverse proxy / allowed-host config)" default:"true"`

	// Logging
	Verbose bool `name:"verbose,v" usage:"Enable verbose logging"`
	Version bool `name:"version" usage:"Show version information"`

	Mode string `name:"mode" env:"MODE" usage:"Mode to run the server in" default:"proxy"`
}

func (c *RootCmd) Run(cobraCmd *cobra.Command, args []string) error {
	if c.Version {
		fmt.Printf("MCP OAuth Proxy\n")
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Built: %s\n", buildTime)
		return nil
	}

	// Configure logging
	if c.Verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Println("Verbose logging enabled")
	}

	// Convert CLI config to internal config format
	config := &types.Config{
		DatabaseDSN:       c.DatabaseDSN,
		OAuthClientID:     c.OAuthClientID,
		OAuthClientSecret: c.OAuthClientSecret,
		OAuthAuthorizeURL: c.OAuthAuthorizeURL,
		OAuthJWKSURL:      c.OAuthJWKSURL,
		OAuthIssuerURL:    c.OAuthIssuerURL,
		ScopesSupported:   c.ScopesSupported,
		MCPServerURL:      c.MCPServerURL,
		EncryptionKey:     c.EncryptionKey,
		Mode:              c.Mode,
		RoutePrefix:       c.RoutePrefix,

		AllowedEmails:              parseCommaList(c.AllowedEmails),
		AllowedEmailsFile:          c.AllowedEmailsFile,
		AllowedEmailDomains:        parseCommaList(c.AllowedEmailDomains),
		AllowedGroups:              parseCommaList(c.AllowedGroups),
		GroupsClaim:                c.GroupsClaim,
		AllowedGoogleHostedDomains: parseCommaList(c.AllowedGoogleHostedDomains),

		AuthorizationHeaderToken: c.AuthorizationHeaderToken,
		IDTokenHeader:            c.IDTokenHeader,

		StripInboundIdentityHeaders: c.StripInboundIdentityHeaders,

		CookieExpire:   c.CookieExpire,
		CookieRefresh:  c.CookieRefresh,
		CookieSecure:   c.CookieSecure,
		CookieSameSite: c.CookieSameSite,

		HealthPath:     c.HealthPath,
		ReadyPath:      c.ReadyPath,
		EnableMetrics:  c.EnableMetrics,
		MetricsPath:    c.MetricsPath,
		MetricsAddress: c.MetricsAddress,

		EnableDynamicClientRegistration: &c.EnableDynamicClientRegistration,

		TrustForwardedHeaders: &c.TrustForwardedHeaders,
	}

	// Validate configuration
	if err := c.validateConfig(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create OAuth proxy
	oauthProxy, err := proxy.NewOAuthProxy(config)
	if err != nil {
		return fmt.Errorf("failed to create OAuth proxy: %w", err)
	}
	defer func() {
		if err := oauthProxy.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Get HTTP handler
	handler := oauthProxy.GetHandler()

	// Tie the proxy's background lifecycle (token cleanup, JWKS refresh) and the
	// servers below to OS signals so everything shuts down cleanly together.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := oauthProxy.Start(ctx); err != nil {
		return fmt.Errorf("failed to start proxy background tasks: %w", err)
	}

	// Start server
	address := fmt.Sprintf("%s:%s", c.Host, c.Port)
	log.Printf("Starting OAuth proxy server on %s", address)
	log.Printf("OAuth Provider: %s", c.OAuthAuthorizeURL)
	log.Printf("MCP Server: %s", c.MCPServerURL)
	log.Printf("Database: %s", c.getDatabaseType())

	mainServer := &http.Server{Addr: address, Handler: handler}

	// Optionally start a SEPARATE metrics listener (METRICS_ADDRESS). When
	// metrics are enabled but no address is configured, the metrics endpoint is
	// served on the main mux instead and no second listener is started.
	var metricsServer *http.Server
	hmCfg := oauthProxy.HealthMetricsConfig()
	if hmCfg.MetricsOnSeparateListener() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle(hmCfg.MetricsPath, oauthProxy.MetricsHandler())
		metricsServer = &http.Server{Addr: hmCfg.MetricsAddress, Handler: metricsMux}
		go func() {
			log.Printf("Starting metrics server on %s%s", hmCfg.MetricsAddress, hmCfg.MetricsPath)
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("Metrics server error: %v", err)
			}
		}()
	}

	// Run the main server in a goroutine so we can wait on the signal context
	// and shut down gracefully.
	serverErr := make(chan error, 1)
	go func() {
		if err := mainServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		// The main server exited on its own (e.g. bind failure).
		c.shutdownMetrics(metricsServer)
		return err
	case <-ctx.Done():
		// Signal received: gracefully drain both servers.
		log.Println("Shutdown signal received, draining servers...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := mainServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("Main server shutdown error: %v", err)
		}
		c.shutdownMetricsCtx(shutdownCtx, metricsServer)
		return nil
	}
}

// shutdownMetrics gracefully shuts down the metrics server (if any) with its
// own short timeout. Used when the main server exits unexpectedly.
func (c *RootCmd) shutdownMetrics(metricsServer *http.Server) {
	if metricsServer == nil {
		return
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.shutdownMetricsCtx(shutdownCtx, metricsServer)
}

// shutdownMetricsCtx gracefully shuts down the metrics server (if any) using
// the provided context.
func (c *RootCmd) shutdownMetricsCtx(ctx context.Context, metricsServer *http.Server) {
	if metricsServer == nil {
		return
	}
	if err := metricsServer.Shutdown(ctx); err != nil {
		log.Printf("Metrics server shutdown error: %v", err)
	}
}

// parseCommaList splits a comma-separated string into a trimmed, non-empty
// slice. An empty input yields a nil slice.
func parseCommaList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (c *RootCmd) validateConfig() error {
	if c.OAuthClientID == "" {
		return fmt.Errorf("oauth-client-id is required")
	}
	if c.OAuthClientSecret == "" {
		return fmt.Errorf("oauth-client-secret is required")
	}
	if c.OAuthAuthorizeURL == "" {
		return fmt.Errorf("oauth-authorize-url is required")
	}
	if c.ScopesSupported == "" {
		return fmt.Errorf("scopes-supported is required")
	}
	if c.MCPServerURL == "" {
		return fmt.Errorf("mcp-server-url is required")
	}
	if c.Mode == proxy.ModeProxy {
		if u, err := url.Parse(c.MCPServerURL); err != nil || u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("invalid MCP server URL: %w", err)
		} else if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("MCP server URL must not contain a path, query, or fragment")
		}
	}
	// Reject health/metrics path collisions and malformed paths up front so the
	// process fails with a clear error instead of panicking http.ServeMux during
	// route setup. Validate the RESOLVED policy so defaults are applied first.
	hmCfg := types.ResolveHealthMetricsConfig(&types.Config{
		HealthPath:     c.HealthPath,
		ReadyPath:      c.ReadyPath,
		EnableMetrics:  c.EnableMetrics,
		MetricsPath:    c.MetricsPath,
		MetricsAddress: c.MetricsAddress,
	})
	if err := hmCfg.Validate(c.RoutePrefix); err != nil {
		return fmt.Errorf("invalid health/metrics configuration: %w", err)
	}
	return nil
}

func (c *RootCmd) getDatabaseType() string {
	if c.DatabaseDSN == "" {
		return "SQLite (data/oauth_proxy.db)"
	}
	if len(c.DatabaseDSN) > 10 && (c.DatabaseDSN[:11] == "postgres://" || c.DatabaseDSN[:14] == "postgresql://") {
		return "PostgreSQL"
	}
	return fmt.Sprintf("SQLite (%s)", c.DatabaseDSN)
}

// Customizer interface implementation for additional command customization
func (c *RootCmd) Customize(cobraCmd *cobra.Command) {
	cobraCmd.Use = "mcp-oauth-proxy"
	cobraCmd.Short = "OAuth 2.1 proxy server for MCP (Model Context Protocol)"
	cobraCmd.Long = `MCP OAuth Proxy is a comprehensive OAuth 2.1 proxy server that provides
OAuth authorization server functionality with PostgreSQL/SQLite storage.

This proxy supports multiple OAuth providers (Google, Microsoft, GitHub) and
proxies requests to MCP servers with user context headers.

Examples:
  # Start with environment variables
  export OAUTH_CLIENT_ID="your-google-client-id"
  export OAUTH_CLIENT_SECRET="your-secret"
  export OAUTH_AUTHORIZE_URL="https://accounts.google.com"
  export SCOPES_SUPPORTED="openid,profile,email"
  export MCP_SERVER_URL="http://localhost:3000"
  mcp-oauth-proxy

  # Start with CLI flags
  mcp-oauth-proxy \
    --oauth-client-id="your-google-client-id" \
    --oauth-client-secret="your-secret" \
    --oauth-authorize-url="https://accounts.google.com" \
    --scopes-supported="openid,profile,email" \
    --mcp-server-url="http://localhost:3000"

  # Use PostgreSQL database
  mcp-oauth-proxy \
    --database-dsn="postgres://user:pass@localhost:5432/oauth_db?sslmode=disable" \
    --oauth-client-id="your-client-id" \
    # ... other required flags

Configuration:
  Configuration values are loaded in this order (later values override earlier ones):
  1. Default values
  2. Environment variables
  3. Command line flags

Database Support:
  - PostgreSQL: Full ACID compliance, recommended for production
  - SQLite: Zero configuration, perfect for development and small deployments`

	cobraCmd.Version = version
}

// Execute is the main entry point for the CLI
func Execute() error {
	rootCmd := &RootCmd{}
	cobraCmd := cmd.Command(rootCmd)
	return cobraCmd.Execute()
}
