package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/authz"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/db"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/encryption"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/authorize"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/callback"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/register"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/revoke"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/success"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/token"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/validate"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/providers"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/ratelimit"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/tokens"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"golang.org/x/oauth2"
)

type OAuthProxy struct {
	metadata        *types.OAuthMetadata
	db              *db.Store
	rateLimiter     *ratelimit.RateLimiter
	providers       *providers.Manager
	tokenManager    *tokens.TokenManager
	provider        string
	encryptionKey   []byte
	resourceName    string
	config          *types.Config
	authorizer      *authz.Authorizer
	idTokenVerifier callback.IDTokenVerifier
	forwardCfg      forwardConfig
	sessionCfg      types.SessionConfig

	// Health & metrics (F6). healthMetricsCfg holds the resolved policy
	// (defaulted paths + the metrics-location decision). readinessPing is the
	// dependency check run by the readiness probe; it defaults to the DB ping
	// and is overridable in tests. metrics holds the Prometheus registry and
	// instruments; it is non-nil only when metrics are enabled.
	healthMetricsCfg types.HealthMetricsConfig
	readinessPing    func(context.Context) error
	metrics          *metricsBundle

	ctx    context.Context
	cancel context.CancelFunc

	// idtokenSleep and idtokenBuild are test seams for buildIDTokenVerifier so
	// the startup retry loop can be exercised without real sleeps or network
	// access. When nil they default to time.Sleep and a real
	// idtoken.MaybeNewVerifier call. Production never sets these.
	idtokenSleep func(time.Duration)
	idtokenBuild func() (callback.IDTokenVerifier, error)

	// idtokenVerifyUnavailable records that id_token verification was EXPECTED
	// (all OIDC params present) but the verifier could NOT be built after
	// retries, so the verifier is nil despite OIDC being configured (H2). It is
	// set ONLY in buildIDTokenVerifier's exhausted-retry/degrade branch and is
	// NOT set for the non-OIDC case (params absent => a nil verifier is
	// legitimate). When set, readiness reports 503 so the pod is taken out of
	// rotation rather than serving traffic with the strongest authz controls
	// (hd/groups/azp/aud/iss signed-claim checks) silently disabled.
	idtokenVerifyUnavailable bool
}

const (
	ModeProxy       = "proxy"
	ModeForwardAuth = "forward_auth"
	ModeMiddleware  = "middleware"
)

func NewOAuthProxy(config *types.Config) (*OAuthProxy, error) {
	databaseDSN := config.DatabaseDSN

	// Log database configuration
	if databaseDSN == "" {
		log.Println("DATABASE_DSN not set, using SQLite database at data/oauth_proxy.db")
	} else if strings.HasPrefix(databaseDSN, "postgres://") || strings.HasPrefix(databaseDSN, "postgresql://") {
		log.Println("Using PostgreSQL database")
	} else {
		log.Printf("Using SQLite database at: %s", databaseDSN)
	}

	if config.Port == "" {
		config.Port = "8080"
	}

	switch config.Mode {
	case "":
		fmt.Println("Defaulting to proxy mode")
		config.Mode = ModeProxy
	case ModeProxy, ModeForwardAuth, ModeMiddleware:
	default:
		return nil, fmt.Errorf("invalid mode: %s", config.Mode)
	}

	if config.Mode == ModeProxy {
		if u, err := url.Parse(config.MCPServerURL); err != nil || u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("invalid MCP server URL: %w", err)
		} else if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("MCP server URL must not contain a path, query, or fragment")
		}
	}

	// Initialize database
	db, err := db.New(databaseDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize rate limiter
	rateLimiter := ratelimit.NewRateLimiter(
		time.Duration(15)*time.Minute,
		5000,
	)

	// Initialize provider manager
	providerManager := providers.NewManager()
	provider := ""

	// Register generic provider
	if config.OAuthClientID != "" && config.OAuthClientSecret != "" && config.OAuthAuthorizeURL != "" {
		genericProvider := providers.NewGenericProvider(config.OAuthAuthorizeURL)
		providerManager.RegisterProvider("generic", genericProvider)
		provider = "generic"
	}

	// Provider JWKS validates provider id_tokens during the callback flow. It
	// must not make arbitrary provider-signed JWTs valid inbound bearer tokens.
	tokenManager, err := tokens.NewTokenManagerWithJWKSURLAndAPIKeyAuth(db, config.APIKeyAuthWebhookURL, "", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token manager: %w", err)
	}

	encryptionKey, err := base64.StdEncoding.DecodeString(config.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	// Build the allowlist authorizer (WHO may use the proxy). The emails file is
	// loaded once here (reload-on-restart only) and merged with the explicit
	// emails list. A zero-config authorizer denies everyone (fail-closed
	// breaking-change default).
	allowedEmails := config.AllowedEmails
	if config.AllowedEmailsFile != "" {
		fileEmails, err := authz.LoadEmailsFile(config.AllowedEmailsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load allowed emails file: %w", err)
		}
		allowedEmails = append(append([]string{}, allowedEmails...), fileEmails...)
	}
	authorizer, err := authz.New(authz.Config{
		Emails:              allowedEmails,
		EmailDomains:        config.AllowedEmailDomains,
		Groups:              config.AllowedGroups,
		GoogleHostedDomains: config.AllowedGoogleHostedDomains,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build authorizer: %w", err)
	}
	if !authorizer.Enabled() {
		log.Println("WARNING: no allowlist configured (ALLOWED_EMAILS / ALLOWED_EMAIL_DOMAINS / ALLOWED_GROUPS / ALLOWED_GOOGLE_HOSTED_DOMAINS): DENYING ALL users. Set ALLOWED_EMAIL_DOMAINS=* to allow any authenticated user.")
	}

	// Resolve and validate the upstream token-forwarding policy (F4f). Reject
	// ambiguous or colliding configs at startup rather than silently picking a
	// winner.
	forwardCfg, err := resolveForwardConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid token forwarding configuration: %w", err)
	}

	// Resolve and validate the session/cookie lifetime + security policy (F5)
	// once at startup. Defaults reproduce the historical hardcoded behavior.
	sessionCfg, err := types.ResolveSessionConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid session/cookie configuration: %w", err)
	}

	// Split and trim scopes to handle whitespace
	scopesSupported := ParseScopesSupported(config.ScopesSupported)

	metadata := &types.OAuthMetadata{
		ResponseTypesSupported:                   []string{"code"},
		CodeChallengeMethodsSupported:            []string{"S256"},
		TokenEndpointAuthMethodsSupported:        []string{"client_secret_post", "none"},
		GrantTypesSupported:                      []string{"authorization_code", "refresh_token"},
		ScopesSupported:                          scopesSupported,
		RevocationEndpointAuthMethodsSupported:   []string{"client_secret_post", "none"},
		RegistrationEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}

	// Create the proxy-owned context up front so background goroutines tied to
	// the proxy lifecycle (notably the id_token verifier's JWKS refresh) are
	// cancelled when Close is called. Start may layer its own cancellation on
	// top, but the verifier built in SetupRoutes must not leak a goroutine bound
	// to context.Background().
	ctx, cancel := context.WithCancel(context.Background())

	// Resolve the health/metrics policy (defaulted paths + metrics-location
	// decision). When metrics are enabled, build the Prometheus registry +
	// instruments up front so they exist regardless of where the handler is
	// mounted (main mux or a separate listener).
	healthMetricsCfg := types.ResolveHealthMetricsConfig(config)
	var metrics *metricsBundle
	if healthMetricsCfg.EnableMetrics {
		metrics = newMetricsBundle()
	}

	p := &OAuthProxy{
		metadata:         metadata,
		db:               db,
		rateLimiter:      rateLimiter,
		providers:        providerManager,
		tokenManager:     tokenManager,
		provider:         provider,
		resourceName:     "MCP Tools",
		encryptionKey:    encryptionKey,
		config:           config,
		authorizer:       authorizer,
		forwardCfg:       forwardCfg,
		sessionCfg:       sessionCfg,
		healthMetricsCfg: healthMetricsCfg,
		metrics:          metrics,
		ctx:              ctx,
		cancel:           cancel,
	}
	// Default the readiness check to a real DB ping; tests may override it.
	p.readinessPing = p.db.Ping
	return p, nil
}

// defaultVerifierRetry is the startup retry policy for building the id_token
// verifier: a handful of attempts with exponential backoff, capped per-attempt.
// With base 500ms, factor 2 and a 5s cap the per-attempt BACKOFF waits are
// 500ms, 1s, 2s, 4s (the 5th attempt needs no wait), i.e. ~7.5s of backoff.
//
// Each attempt may ALSO spend up to the JWKS HTTP timeout
// (idtoken.defaultJWKSHTTPTimeout, ~10s) actually fetching the JWKS before it
// fails, so the worst-case boot delay when the endpoint hangs is roughly
// 5*10s (fetches) + 7.5s (backoff) ~= 57s before degrading-with-warning.
// Connection-refused/500 responses fail fast, so the common transient-outage
// case is dominated by the ~7.5s of backoff. The HTTP timeout bounds the hung
// case so boot cannot block indefinitely.
var defaultVerifierRetry = retryKnobs{
	attempts: 5,
	base:     500 * time.Millisecond,
	factor:   2,
	cap:      5 * time.Second,
}

// retryKnobs configures buildVerifierWithRetry's exponential backoff. It is a
// small struct so tests can dial the schedule down (and inject a fake sleeper)
// to run without real sleeps.
type retryKnobs struct {
	attempts int           // total build attempts (>= 1)
	base     time.Duration // first backoff wait
	factor   int           // multiplier applied to the wait each attempt
	cap      time.Duration // per-attempt wait ceiling
}

// backoffFor returns the wait to use BEFORE the (attempt+1)-th retry, i.e. the
// wait after a failed attempt at zero-based index `attempt`. It grows
// base*factor^attempt, clamped to cap. Kept pure so the schedule is unit
// testable without sleeping.
func (k retryKnobs) backoffFor(attempt int) time.Duration {
	wait := k.base
	for i := 0; i < attempt; i++ {
		wait *= time.Duration(k.factor)
		if k.cap > 0 && wait >= k.cap {
			return k.cap
		}
	}
	if k.cap > 0 && wait > k.cap {
		return k.cap
	}
	return wait
}

// buildVerifierWithRetry calls build up to knobs.attempts times, sleeping
// between failed attempts using the exponential backoff schedule and the
// injected sleep func. It stops early (returning ctx.Err) if ctx is cancelled,
// so shutdown aborts the loop. On the first success it returns the verifier;
// after the last failed attempt it returns the final build error. Injecting
// sleep and build keeps it fully unit-testable without real sleeps or network.
func buildVerifierWithRetry(ctx context.Context, knobs retryKnobs, sleep func(time.Duration), build func() (callback.IDTokenVerifier, error)) (callback.IDTokenVerifier, error) {
	if knobs.attempts < 1 {
		knobs.attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < knobs.attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			return nil, lastErr
		}

		verifier, err := build()
		switch {
		case err != nil:
			lastErr = err
		case verifier == nil:
			// A nil verifier with a nil error is NOT success: success must yield
			// a usable verifier. Treat it as a retryable error so the loop does
			// not silently return nil as if verification were configured.
			lastErr = errors.New("idtoken: build returned a nil verifier without an error")
		default:
			return verifier, nil
		}

		// No backoff after the final attempt.
		if attempt == knobs.attempts-1 {
			break
		}

		// Wait for the backoff OR context cancellation, whichever comes first,
		// so a shutdown during the wait aborts promptly instead of blocking for
		// the full backoff. The injected sleep runs in a goroutine and signals
		// when it returns; ctx.Done races against it.
		done := make(chan struct{})
		go func() {
			sleep(knobs.backoffFor(attempt))
			close(done)
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
		}
	}
	return nil, lastErr
}

// buildIDTokenVerifier constructs the OIDC id_token verifier from the provider
// parameters in config: the issuer is derived from the OAuth authorize URL
// origin, the JWKS URL comes from config, and the expected audience is the
// OAuth client ID. It returns a true nil interface (not a typed nil) when the
// verifier cannot or should not be built, so the callback treats it as "no
// id_token verification".
//
// Behavior:
//   - Non-OIDC setup (issuer/JWKS/client ID not all present): MaybeNewVerifier
//     would return (nil, nil), so there is nothing to build. Return nil
//     immediately with no retry and no warning.
//   - OIDC params present but the build fails (e.g. a JWKS blip at startup):
//     retry with exponential backoff. If every attempt fails, log a WARNING
//     that id_token verification is DISABLED for this process (security impact)
//     and degrade to nil rather than hard-exiting.
//   - When a verifier is built and OAUTH_ISSUER_URL is empty, the issuer was
//     derived from the authorize URL's origin, which is wrong for path-based
//     issuers; emit a WARNING pointing at OAUTH_ISSUER_URL.
func (p *OAuthProxy) buildIDTokenVerifier() callback.IDTokenVerifier {
	// Use the explicitly configured issuer when set (required for path-based
	// issuers like Keycloak https://host/realms/x); otherwise derive it from the
	// authorize URL's origin.
	issuer := p.config.OAuthIssuerURL
	if issuer == "" {
		issuer = oidcIssuerFromAuthorizeURL(p.config.OAuthAuthorizeURL)
	}

	// A verifier is only EXPECTED when all OIDC params are present; this mirrors
	// MaybeNewVerifier's (nil, nil) guard. When any is missing this is a
	// non-OIDC setup: return nil immediately with no retry and no warning.
	if issuer == "" || p.config.OAuthJWKSURL == "" || p.config.OAuthClientID == "" {
		return nil
	}

	// Bind the verifier's JWKS background refresh to the proxy-owned context so
	// it is cancelled in Close rather than leaking against context.Background().
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	build := p.idtokenBuild
	if build == nil {
		build = func() (callback.IDTokenVerifier, error) {
			v, err := idtoken.MaybeNewVerifier(ctx, idtoken.Config{
				Issuer:      issuer,
				JWKSURL:     p.config.OAuthJWKSURL,
				Audience:    p.config.OAuthClientID,
				GroupsClaim: p.config.GroupsClaim,
			})
			if err != nil {
				return nil, err
			}
			// Params are present (checked above), so MaybeNewVerifier should
			// always return a non-nil verifier. A nil verifier with a nil error
			// here is unexpected/defensive: surface it as an ERROR so the retry
			// loop retries and ultimately emits the DISABLED warning, rather
			// than treating it as silent success.
			if v == nil {
				return nil, fmt.Errorf("idtoken: MaybeNewVerifier returned a nil verifier despite OIDC params being present (issuer=%s)", issuer)
			}
			return v, nil
		}
	}

	sleep := p.idtokenSleep
	if sleep == nil {
		sleep = time.Sleep
	}

	verifier, err := buildVerifierWithRetry(ctx, defaultVerifierRetry, sleep, build)
	if err != nil {
		// Every attempt failed. Degrade rather than hard-exit, but make the
		// security impact loud: with no verifier, group/hosted-domain allowlist
		// rules can never match and email rules lose signature/iss/aud checks.
		log.Printf("WARNING: id_token verification is DISABLED for this process: failed to build the OIDC id_token verifier after retries: %v. "+
			"Group and hosted-domain authorization rules will not match and email rules lose signature/issuer/audience guarantees. "+
			"Restart once the JWKS endpoint (%s) is reachable.", err, p.config.OAuthJWKSURL)
		// Verification was EXPECTED (params present, checked above) but could not
		// be built. Record this so readiness fails closed (503) and the pod is
		// taken out of rotation rather than serving with verification disabled.
		// This is set ONLY here: the non-OIDC early return above never reaches it.
		p.idtokenVerifyUnavailable = true
		return nil
	}
	if verifier == nil {
		// Defensive: params were present so this is unexpected, but treat it as
		// no verification rather than returning a typed nil.
		return nil
	}

	// The issuer was derived (no explicit override). Warn that this is wrong for
	// path-based issuers so operators can set OAUTH_ISSUER_URL if logins fail.
	if p.config.OAuthIssuerURL == "" {
		log.Printf("WARNING: the expected id_token issuer was derived from OAUTH_AUTHORIZE_URL's origin (%q) and may be wrong for path-based issuers "+
			"(e.g. Keycloak https://host/realms/x, Azure AD v2 tenant). Set OAUTH_ISSUER_URL explicitly if logins fail with an issuer-mismatch.", issuer)
	}

	return verifier
}

// idTokenVerificationUnavailable reports whether id_token verification was
// EXPECTED (all OIDC params configured) but the verifier could not be built,
// leaving the strongest signed-claim authorization controls disabled. Readiness
// uses this to fail closed (503) so the instance takes no traffic. It is never
// true for a non-OIDC setup, where a nil verifier is legitimate.
func (p *OAuthProxy) idTokenVerificationUnavailable() bool {
	return p.idtokenVerifyUnavailable
}

// oidcIssuerFromAuthorizeURL derives the expected id_token issuer ("iss") from
// the OAuth authorize URL by taking its scheme://host origin. Most OIDC
// providers (e.g. Google's https://accounts.google.com) issue id_tokens whose
// "iss" equals this origin.
func oidcIssuerFromAuthorizeURL(authorizeURL string) string {
	if authorizeURL == "" {
		return ""
	}
	parsed, err := url.Parse(authorizeURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
}

// GetOAuthClientID returns the OAuth client ID from config
func (p *OAuthProxy) GetOAuthClientID() string {
	return p.config.OAuthClientID
}

// GetOAuthClientSecret returns the OAuth client secret from config
func (p *OAuthProxy) GetOAuthClientSecret() string {
	return p.config.OAuthClientSecret
}

// GetOAuthAuthorizeURL returns the OAuth authorization URL from config
func (p *OAuthProxy) GetOAuthAuthorizeURL() string {
	return p.config.OAuthAuthorizeURL
}

// GetMCPServerURL returns the MCP server URL from config
func (p *OAuthProxy) GetMCPServerURL() string {
	return p.config.MCPServerURL
}

func (p *OAuthProxy) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *OAuthProxy) Start(ctx context.Context) error {
	// The proxy already owns a cancellable context created in NewOAuthProxy
	// (used by the id_token verifier's JWKS refresh started in SetupRoutes).
	// Tie that context to the caller's ctx so cancelling ctx also tears down
	// proxy background goroutines, while Close still cancels everything via the
	// original p.cancel. We deliberately do NOT replace p.ctx/p.cancel here so
	// the verifier's refresh goroutine stays bound to the proxy lifecycle.
	if p.ctx == nil {
		p.ctx, p.cancel = context.WithCancel(context.Background())
	}
	if ctx != nil {
		context.AfterFunc(ctx, func() {
			if p.cancel != nil {
				p.cancel()
			}
		})
	}

	// Setup cleanup goroutine for expired tokens. Stop both the ticker AND the
	// goroutine when the proxy context is cancelled: time.Ticker.Stop() does not
	// close ticker.C, so a bare `for range ticker.C` would block forever after
	// cancellation and leak the goroutine. Select on ctx.Done() instead.
	go func() {
		ticker := time.NewTicker(time.Hour) // Cleanup every hour
		defer ticker.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				if err := p.db.CleanupExpiredTokens(); err != nil {
					log.Printf("Failed to cleanup expired tokens: %v", err)
				}
			}
		}
	}()

	return nil
}

func (p *OAuthProxy) SetupRoutes(mux *http.ServeMux, next http.Handler) {
	provider, err := p.providers.GetProvider(p.provider)
	if err != nil {
		log.Fatalf("Failed to get provider: %v", err)
	}

	if p.config.CookieNamePrefix == "" {
		p.config.CookieNamePrefix = "mcp_oauth_proxy_"
	} else if !strings.HasSuffix(p.config.CookieNamePrefix, "_") && !strings.HasSuffix(p.config.CookieNamePrefix, "-") {
		p.config.CookieNamePrefix += "_"
	}

	// Build the OIDC id_token verifier from the provider's OIDC parameters.
	// This is shared infra (V0): when the IdP issues an id_token it is verified
	// and its claims are stored in the grant for later authorization features.
	// The verifier is optional - buildIDTokenVerifier returns nil for non-OIDC
	// setups (no JWKS URL configured) so the callback simply skips id_token
	// verification rather than failing.
	idTokenVerifier := p.buildIDTokenVerifier()
	p.idTokenVerifier = idTokenVerifier

	authorizeHandler := authorize.NewHandler(p.db, provider, p.metadata.ScopesSupported, p.GetOAuthClientID(), p.GetOAuthClientSecret(), p.config.RoutePrefix)
	tokenHandler := token.NewHandler(p.db, p.authorizer, p.encryptionKey, p.sessionCfg)
	callbackHandler := callback.NewHandler(p.db, provider, p.encryptionKey, p.GetOAuthClientID(), p.GetOAuthClientSecret(), p.config.RoutePrefix, p.config.CookieNamePrefix, idTokenVerifier, p.authorizer, p.sessionCfg)
	revokeHandler := revoke.NewHandler(p.db)
	tokenValidator := validate.NewTokenValidator(p.tokenManager, p.encryptionKey, p.db, provider, p.config.RoutePrefix, p.GetOAuthClientID(), p.GetOAuthClientSecret(), p.config.CookieNamePrefix, p.config.MCPServerID, p.metadata.ScopesSupported, p.config.MCPPaths, p.authorizer, idTokenVerifier, p.sessionCfg)
	successHandler := success.NewHandler()

	// Get route prefix from config
	prefix := p.config.RoutePrefix

	// Legacy liveness route. Register it unless its fully-qualified pattern
	// already equals a configured probe/metrics pattern that
	// registerHealthMetricsRoutes mounts on the main mux below. In the common
	// case of an empty prefix with HEALTH_PATH=/health the liveness probe serves
	// the exact same path with the same handler, so skipping the duplicate keeps
	// /health back-compat intact while avoiding an http.ServeMux panic on a
	// duplicate "GET /health" registration. A genuine collision with ReadyPath
	// or main-mux MetricsPath is rejected earlier by HealthMetricsConfig.Validate.
	legacyHealth := prefix + "/health"
	hm := p.healthMetricsCfg
	collidesWithProbe := legacyHealth == hm.HealthPath || legacyHealth == hm.ReadyPath ||
		(hm.MetricsOnMainMux() && legacyHealth == hm.MetricsPath)
	if !collidesWithProbe {
		mux.HandleFunc("GET "+legacyHealth, p.withCORS(p.healthHandler))
	}

	// Health & metrics endpoints (F6). These are registered at the ROOT (never
	// under RoutePrefix) so probes have stable paths, mirroring how the
	// .well-known/* metadata is mounted. They are exact paths so they do not
	// collide with the catch-all "/{path...}" proxy route, and they are NOT
	// wrapped in withRateLimit or token validation so probes always work
	// unauthenticated. CORS is applied for consistency.
	p.registerHealthMetricsRoutes(mux)

	// OAuth endpoints
	mux.HandleFunc("GET "+prefix+"/authorize", p.withCORS(p.withRateLimit(authorizeHandler)))
	mux.HandleFunc("GET "+prefix+"/callback", p.withCORS(p.withRateLimit(callbackHandler)))
	mux.HandleFunc("POST "+prefix+"/token", p.withCORS(p.withRateLimit(tokenHandler)))
	mux.HandleFunc("POST "+prefix+"/revoke", p.withCORS(p.withRateLimit(revokeHandler)))
	mux.HandleFunc("POST "+prefix+"/register", p.withCORS(p.withRateLimit(register.NewHandler(p.db, p.config.DCREnabled()))))

	// Metadata endpoints
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", p.withCORS(p.oauthMetadataHandler))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", p.withCORS(p.protectedResourceMetadataHandler))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{path...}", p.withCORS(p.protectedResourceMetadataHandler))

	mux.HandleFunc("GET "+prefix+"/auth/mcp-ui/success", p.withCORS(p.withRateLimit(successHandler)))

	// Protect everything else
	mux.HandleFunc(prefix+"/{path...}", p.withCORS(p.withRateLimit(tokenValidator.WithTokenValidation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mcpProxyHandler(w, r, next)
	})))))
}

// GetHandler returns an http.Handler for the OAuth proxy
func (p *OAuthProxy) GetHandler() http.Handler {
	mux := http.NewServeMux()
	p.SetupRoutes(mux, nil)

	// Wrap with logging middleware
	loggedHandler := handlers.LoggingHandler(os.Stdout, mux)

	// Instrument the whole handler with Prometheus middleware when metrics are
	// enabled. This counts every request (by code/method) and records request
	// duration, including the probe and metrics endpoints themselves.
	var handler http.Handler = loggedHandler
	if p.metrics != nil {
		handler = p.metrics.instrument(loggedHandler)
	}

	// The resolved "trust forwarded headers" policy is injected per-route by
	// withCORS (the shared wrapper applied to every route in SetupRoutes), so it
	// holds regardless of whether the proxy is served via GetHandler or via a
	// direct SetupRoutes call. No additional outer wrapper is needed here.
	return handler
}

// withCORS wraps a handler with CORS headers. It is the shared per-route
// wrapper applied to EVERY route registered by SetupRoutes (OAuth, metadata,
// health/ready/metrics, and the catch-all proxy route), so it also injects the
// resolved "trust forwarded headers" policy into the request context here. This
// guarantees the policy holds for direct-SetupRoutes callers (embedding /
// middleware mode), not just for GetHandler. The injection is idempotent and
// always writes the same configured value, so a redundant outer wrapper (if
// any) is harmless.
func (p *OAuthProxy) withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(handlerutils.WithTrustForwarded(r.Context(), p.config.TrustForwardedHeadersEnabled()))

		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, mcp-protocol-version")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(int((12 * time.Hour).Seconds())))

		// Handle preflight OPTIONS request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// withRateLimit wraps a handler with rate limiting
func (p *OAuthProxy) withRateLimit(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.rateLimiter != nil {
			clientIP := handlerutils.GetClientIP(r)
			if !p.rateLimiter.Allow(clientIP) {
				handlerutils.JSON(w, http.StatusTooManyRequests, types.OAuthError{
					Error:            "too_many_requests",
					ErrorDescription: "Rate limit exceeded",
				})
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

func (p *OAuthProxy) healthHandler(w http.ResponseWriter, r *http.Request) {
	handlerutils.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (p *OAuthProxy) oauthMetadataHandler(w http.ResponseWriter, r *http.Request) {
	baseURL := handlerutils.GetBaseURL(r)
	prefix := p.config.RoutePrefix

	// Create dynamic metadata based on the request
	metadata := &types.OAuthMetadata{
		Issuer:                                 baseURL,
		ServiceDocumentation:                   p.metadata.ServiceDocumentation,
		AuthorizationEndpoint:                  fmt.Sprintf("%s%s/authorize", baseURL, prefix),
		ResponseTypesSupported:                 p.metadata.ResponseTypesSupported,
		CodeChallengeMethodsSupported:          p.metadata.CodeChallengeMethodsSupported,
		TokenEndpoint:                          fmt.Sprintf("%s%s/token", baseURL, prefix),
		TokenEndpointAuthMethodsSupported:      p.metadata.TokenEndpointAuthMethodsSupported,
		GrantTypesSupported:                    p.metadata.GrantTypesSupported,
		ScopesSupported:                        p.metadata.ScopesSupported,
		RevocationEndpoint:                     fmt.Sprintf("%s%s/revoke", baseURL, prefix),
		RevocationEndpointAuthMethodsSupported: p.metadata.RevocationEndpointAuthMethodsSupported,
	}

	// Only advertise Dynamic Client Registration when it is enabled (F2). When
	// disabled, omit both registration fields (they use omitempty) so clients do
	// not attempt DCR against an endpoint that returns 403.
	if p.config.DCREnabled() {
		metadata.RegistrationEndpoint = fmt.Sprintf("%s%s/register", baseURL, prefix)
		metadata.RegistrationEndpointAuthMethodsSupported = p.metadata.RegistrationEndpointAuthMethodsSupported
	}

	handlerutils.JSON(w, http.StatusOK, metadata)
}

func (p *OAuthProxy) protectedResourceMetadataHandler(w http.ResponseWriter, r *http.Request) {
	baseURL := handlerutils.GetBaseURL(r)
	prefix := p.config.RoutePrefix
	resourceURL := strings.TrimSuffix(baseURL+prefix, "/")

	metadata := types.OAuthProtectedResourceMetadata{
		Resource:              resourceURL,
		AuthorizationServers:  []string{baseURL + prefix},
		Scopes:                p.metadata.ScopesSupported,
		ResourceName:          p.resourceName,
		ResourceDocumentation: p.metadata.ServiceDocumentation,
	}

	handlerutils.JSON(w, http.StatusOK, metadata)
}

func (p *OAuthProxy) mcpProxyHandler(w http.ResponseWriter, r *http.Request, next http.Handler) {
	tokenInfo := validate.GetTokenInfo(r)
	path := r.PathValue("path")

	// Check if the access token is expired and refresh if needed
	if tokenInfo != nil && tokenInfo.Props != nil {
		if _, ok := tokenInfo.Props["access_token"].(string); ok {
			// Check if token is expired (with a 5-minute buffer)
			expiresAt, ok := tokenInfo.Props["expires_at"].(float64)
			if ok && expiresAt > 0 {
				if time.Now().Add(5 * time.Minute).After(time.Unix(int64(expiresAt), 0)) {
					log.Printf("Access token is expired or will expire soon, attempting to refresh")

					// Get the refresh token
					refreshToken, ok := tokenInfo.Props["refresh_token"].(string)
					if !ok || refreshToken == "" {
						log.Printf("No refresh token available, cannot refresh access token")
						// Agent re-auth challenge (F7): a bare 401 here would leave an
						// MCP agent unable to re-run discovery. Emit the shared
						// WWW-Authenticate challenge so it can re-authenticate.
						handlerutils.WriteBearerChallenge(w, r, "Access token expired and no refresh token available")
						return
					}

					// Get the provider
					provider, err := p.providers.GetProvider(p.provider)
					if err != nil {
						log.Printf("Failed to get provider for token refresh: %v", err)
						handlerutils.JSON(w, http.StatusInternalServerError, map[string]string{
							"error":             "server_error",
							"error_description": "Failed to refresh token",
						})
						return
					}

					// Get provider credentials
					clientID := p.GetOAuthClientID()
					clientSecret := p.GetOAuthClientSecret()
					if clientID == "" || clientSecret == "" {
						log.Printf("OAuth credentials not configured for token refresh")
						handlerutils.JSON(w, http.StatusInternalServerError, map[string]string{
							"error":             "server_error",
							"error_description": "OAuth credentials not configured",
						})
						return
					}

					// Refresh the token
					newTokenInfo, err := provider.RefreshToken(r.Context(), refreshToken, clientID, clientSecret)
					if err != nil {
						log.Printf("Failed to refresh token: %v", err)
						// Agent re-auth challenge (F7): the upstream refresh was
						// rejected. Return 401 WITH the challenge (never a 500, never a
						// bare 401) so the agent re-runs discovery / PKCE.
						handlerutils.WriteBearerChallenge(w, r, "Failed to refresh access token")
						return
					}

					// Re-check the allowlist on every IdP token refresh (user
					// decision). Re-derive the identity from a fresh id_token if
					// the provider returned one (re-verifying and updating the
					// stored claims), otherwise from the stored claims/userinfo.
					// On deny: revoke the session and return 401 so the agent
					// re-runs discovery. Never a 500.
					refreshedProps, denied := p.reauthorizeOnRefresh(r.Context(), tokenInfo.Props, newTokenInfo)
					if denied != nil {
						// Only revoke the whole session on an actual authorization
						// DENY. On an infrastructure error (e.g. a transient
						// id_token verify failure) we fail closed for THIS request
						// but keep the session so a blip does not log everyone out
						// (CONCERN 2). Either way: 401, never 500.
						// The challenge message must match what actually happened: a
						// genuine deny revokes the session and says so; a transient
						// infra failure preserves the session and must NOT claim the
						// access was revoked.
						challenge := "Re-authorization failed; please re-authenticate"
						if errors.Is(denied, authz.ErrDenied) {
							log.Printf("authorization revoked on refresh for user=%q: %v", tokenInfo.UserID, denied)
							p.revokeGrantOnDeny(r, tokenInfo.GrantID)
							challenge = "Access revoked: you are no longer authorized to use this resource"
						} else {
							log.Printf("authorization re-check failed on refresh for user=%q (session preserved): %v", tokenInfo.UserID, denied)
						}
						// Agent re-auth challenge (F7): the session revoke above (on a
						// genuine deny) precedes this write. Emit 401 WITH the challenge
						// (not a bare 401) so the agent can re-run discovery; on a
						// genuine deny the revoked session forces a fresh authorization.
						handlerutils.WriteBearerChallenge(w, r, challenge)
						return
					}
					tokenInfo.Props = refreshedProps

					// Update the grant with new token information
					if err := p.updateGrant(tokenInfo.GrantID, tokenInfo.UserID, tokenInfo, newTokenInfo); err != nil {
						log.Printf("Failed to update grant: %v", err)
						handlerutils.JSON(w, http.StatusInternalServerError, map[string]string{
							"error":             "server_error",
							"error_description": "Failed to update grant with new token",
						})
						return
					}

					// Update the token info with the new access token for the current request
					tokenInfo.Props["access_token"] = newTokenInfo.AccessToken
					log.Printf("Successfully refreshed access token")
				}
			}
		}
	}

	switch p.config.Mode {
	case ModeMiddleware:
		next.ServeHTTP(w, r)
	case ModeForwardAuth:
		p.setHeaders(w.Header(), tokenInfo.Props)
	case ModeProxy:
		// Create target URL
		targetURL := p.GetMCPServerURL() + "/" + path
		// Log the proxy request for debugging
		log.Printf("Proxying request: %s %s -> %s", r.Method, r.URL.Path, targetURL)

		// Create reverse proxy
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.Header.Set("X-Forwarded-Host", req.Host)
				req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)

				newURL, _ := url.Parse(targetURL)
				req.URL.Scheme = newURL.Scheme
				req.URL.Host = newURL.Host
				req.Host = newURL.Host

				// Add forwarded headers from token props. setHeaders deletes any
				// inbound Authorization first, then applies the configured
				// forwarding policy, so a forwarded token (if any) is the final
				// Authorization value.
				p.setHeaders(req.Header, tokenInfo.Props)
			},
			ModifyResponse: func(resp *http.Response) error {
				// Rewrite Location header to use proxy host instead of downstream server host
				if location := resp.Header.Get("Location"); location != "" {
					if locationURL, err := url.Parse(location); err == nil {
						// Get the original request to extract proxy host
						proxyHost := resp.Request.Header.Get("X-Forwarded-Host")
						if proxyHost != "" {
							// Parse downstream server URL to get scheme
							downstreamURL, _ := url.Parse(p.GetMCPServerURL())

							// Only rewrite if the location points to the downstream server
							if locationURL.Host == downstreamURL.Host {
								locationURL.Scheme = resp.Request.URL.Scheme
								locationURL.Host = proxyHost
								resp.Header.Set("Location", locationURL.String())
							}
						}
					}
				}
				return nil
			},
			ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
				log.Printf("Proxy error: %v", err)
				rw.WriteHeader(http.StatusBadGateway)
			},
		}

		// Serve the proxied request
		proxy.ServeHTTP(w, r)
	}
}

// setHeaders writes the X-Forwarded-* identity headers from the grant props and
// then applies the resolved upstream token-forwarding policy (F4f).
//
// Any inbound Authorization is deleted FIRST so a spoofed value can never
// survive into the upstream request, regardless of policy. The forwarding
// policy then sets the Authorization (or the configured custom id_token header)
// when configured to do so. This makes both call sites (the proxy Director and
// forward_auth mode) consistent and spoof-safe.
func (p *OAuthProxy) setHeaders(header http.Header, props map[string]any) {
	// F3: optional inbound header hygiene. When enabled, strip the full family of
	// client-supplied identity / forwarded headers (including the configured
	// ID_TOKEN_HEADER and headers the proxy does not otherwise manage) BEFORE
	// writing the proxy's own derived headers below, so spoofed inbound values
	// cannot survive. Default (disabled) leaves the broader set untouched; only
	// the four managed headers + Authorization are neutralized as before.
	if p.config != nil && p.config.StripInboundIdentityHeaders {
		p.forwardCfg.stripInboundIdentityHeaders(header)
	}

	header.Del(authorizationHeader)

	if userID, ok := props["user_id"].(string); ok {
		header.Set("X-Forwarded-User", userID)
	} else {
		header.Del("X-Forwarded-User")
	}
	if email, ok := props["email"].(string); ok {
		header.Set("X-Forwarded-Email", email)
	} else {
		header.Del("X-Forwarded-Email")
	}
	if name, ok := props["name"].(string); ok {
		header.Set("X-Forwarded-Name", name)
	} else {
		header.Del("X-Forwarded-Name")
	}
	if accessToken, ok := props["access_token"].(string); ok {
		header.Set("X-Forwarded-Access-Token", accessToken)
	} else {
		header.Del("X-Forwarded-Access-Token")
	}

	// Apply the configured upstream auth header(s) AFTER deleting any inbound
	// Authorization, so forwarding writes the final value.
	p.forwardCfg.applyForwarding(header, props)
}

// reauthorizeOnRefresh re-derives the user's identity after an IdP token refresh
// and re-runs the allowlist. If the refresh returned a fresh id_token it is
// re-verified (V0) and the stored claims are updated; otherwise the identity is
// taken from the previously stored claims/userinfo. It returns the (possibly
// updated) props to persist, and a non-nil error when the user is no longer
// authorized (the caller must revoke and emit 401/redirect, never 500).
func (p *OAuthProxy) reauthorizeOnRefresh(ctx context.Context, oldProps map[string]any, newTokenInfo *oauth2.Token) (map[string]any, error) {
	// Copy so we never mutate the caller's map on the deny path.
	props := map[string]any{}
	maps.Copy(props, oldProps)

	// If the provider returned a fresh id_token and we have a verifier, verify
	// it and refresh the stored claims so authorization uses current data.
	if p.idTokenVerifier != nil && newTokenInfo != nil {
		if rawIDToken, _ := newTokenInfo.Extra("id_token").(string); rawIDToken != "" {
			claims, err := p.idTokenVerifier.Verify(ctx, rawIDToken)
			if err != nil {
				// A returned-but-invalid id_token must fail closed.
				return props, fmt.Errorf("failed to verify refreshed id_token: %w", err)
			}
			if claimsJSON, mErr := json.Marshal(claims); mErr == nil {
				props["id_token_claims"] = string(claimsJSON)
				props["id_token"] = rawIDToken
				// Refresh the stored id_token exp alongside the token so the
				// forwarding staleness check uses the fresh token's OWN exp
				// (Unix seconds), distinct from props["expires_at"] (the IdP
				// access-token expiry).
				props["id_token_exp"] = claims.ExpiresAt
			}
		}
	}

	if p.authorizer == nil {
		// Fail closed: a missing authorizer must deny, never allow (CONCERN 1).
		return props, authz.ErrDenied
	}

	identity := authz.IdentityFromStoredProps(props)
	if err := p.authorizer.Authorize(identity); err != nil {
		return props, err
	}
	return props, nil
}

// revokeGrantOnDeny revokes the WHOLE session for a grant whose authorization
// was revoked on refresh, forcing the client to re-authenticate. Revoking by
// grant kills every token (access and refresh, across rotations) for the
// session, not just the inbound bearer, so a browser holding a refresh-token
// cookie cannot continue (BLOCKER 2). The inbound bearer is also revoked
// defensively in case it has no grant association.
func (p *OAuthProxy) revokeGrantOnDeny(r *http.Request, grantID string) {
	if grantID != "" {
		if err := p.db.RevokeTokensByGrant(grantID); err != nil {
			log.Printf("Failed to revoke session by grant after authorization deny: %v", err)
		}
	}
	if bearer := validate.GetBearerToken(r); bearer != "" {
		if err := p.db.RevokeToken(bearer); err != nil {
			log.Printf("Failed to revoke bearer token after authorization deny: %v", err)
		}
	}
}

// updateGrant updates a grant with new token information
func (p *OAuthProxy) updateGrant(grantID, userID string, oldTokenInfo *tokens.TokenInfo, newTokenInfo *oauth2.Token) error {
	// Get the existing grant
	grant, err := p.db.GetGrant(grantID, userID)
	if err != nil {
		return fmt.Errorf("failed to get grant: %w", err)
	}

	sensitiveProps := map[string]any{}
	if oldTokenInfo.Props != nil {
		// keep all the old props, that include a lot of the user info
		maps.Copy(sensitiveProps, oldTokenInfo.Props)
	}

	// Prepare sensitive props data
	sensitiveProps["access_token"] = newTokenInfo.AccessToken
	sensitiveProps["refresh_token"] = newTokenInfo.RefreshToken
	sensitiveProps["expires_at"] = newTokenInfo.Expiry.Unix()

	// Add existing user info if available
	if grant.Props != nil {
		if email, ok := grant.Props["email"].(string); ok {
			sensitiveProps["email"] = email
		}
		if name, ok := grant.Props["name"].(string); ok {
			sensitiveProps["name"] = name
		}
		if userID, ok := grant.Props["user_id"].(string); ok {
			sensitiveProps["user_id"] = userID
		}
	}

	// use old refresh token in case new one is not provided
	if sensitiveProps["refresh_token"] == "" {
		sensitiveProps["refresh_token"] = oldTokenInfo.Props["refresh_token"]
	}

	// Initialize props map
	props := make(map[string]any)

	// Encrypt the sensitive props data
	encryptedProps, err := encryption.EncryptData(sensitiveProps, p.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt props data: %w", err)
	}

	// Store encrypted data
	props["encrypted_data"] = encryptedProps.Data
	props["iv"] = encryptedProps.IV
	props["algorithm"] = encryptedProps.Algorithm
	props["encrypted"] = true

	// Update the grant with new props
	grant.Props = props

	// Update the grant in the database
	if err := p.db.UpdateGrant(grant); err != nil {
		return fmt.Errorf("failed to update grant: %w", err)
	}

	return nil
}

// ParseScopesSupported parses a comma-separated scopes string and trims whitespace from each scope.
func ParseScopesSupported(envScopes string) []string {
	scopesRaw := strings.Split(envScopes, ",")
	scopesSupported := make([]string, 0, len(scopesRaw))
	for _, scope := range scopesRaw {
		if trimmed := strings.TrimSpace(scope); trimmed != "" {
			scopesSupported = append(scopesSupported, trimmed)
		}
	}
	return scopesSupported
}
