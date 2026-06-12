package proxy

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/callback"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/require"
)

// okVerifier satisfies callback.IDTokenVerifier for success-path assertions.
// The embedded nil interface is never called; tests only assert identity.
type okVerifier struct{ callback.IDTokenVerifier }

func TestBuildVerifierWithRetry_SucceedsAfterTransientFailures(t *testing.T) {
	var slept []time.Duration
	sleep := func(d time.Duration) { slept = append(slept, d) }

	calls := 0
	want := okVerifier{}
	build := func() (callback.IDTokenVerifier, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("transient JWKS error")
		}
		return want, nil
	}

	got, err := buildVerifierWithRetry(context.Background(), retryKnobs{
		attempts: 5,
		base:     500 * time.Millisecond,
		factor:   2,
		cap:      8 * time.Second,
	}, sleep, build)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != callback.IDTokenVerifier(want) {
		t.Fatalf("expected the verifier from the successful build, got %#v", got)
	}
	if calls != 3 {
		t.Fatalf("expected build called 3 times, got %d", calls)
	}
	// Slept once between each of the 2 failures and the success: N-1 = 2 sleeps.
	if len(slept) != 2 {
		t.Fatalf("expected 2 sleeps (N-1), got %d: %v", len(slept), slept)
	}
	// Exponential backoff: 500ms, then 1s.
	if slept[0] != 500*time.Millisecond || slept[1] != 1*time.Second {
		t.Fatalf("expected backoff [500ms 1s], got %v", slept)
	}
}

func TestBuildVerifierWithRetry_ExhaustedReturnsError(t *testing.T) {
	var slept []time.Duration
	sleep := func(d time.Duration) { slept = append(slept, d) }

	calls := 0
	build := func() (callback.IDTokenVerifier, error) {
		calls++
		return nil, errors.New("always down")
	}

	got, err := buildVerifierWithRetry(context.Background(), retryKnobs{
		attempts: 5,
		base:     500 * time.Millisecond,
		factor:   2,
		cap:      4 * time.Second,
	}, sleep, build)
	if err == nil {
		t.Fatalf("expected error after exhausting attempts")
	}
	if got != nil {
		t.Fatalf("expected nil verifier on exhaustion, got %#v", got)
	}
	if calls != 5 {
		t.Fatalf("expected 5 build attempts, got %d", calls)
	}
	// Sleeps happen between attempts only: attempts-1 = 4.
	if len(slept) != 4 {
		t.Fatalf("expected 4 sleeps, got %d: %v", len(slept), slept)
	}
	// Backoff capped at 4s: 500ms, 1s, 2s, then 4s (would be 4s, at cap).
	want := []time.Duration{500 * time.Millisecond, 1 * time.Second, 2 * time.Second, 4 * time.Second}
	for i := range want {
		if slept[i] != want[i] {
			t.Fatalf("backoff mismatch at %d: want %v got %v (all=%v)", i, want[i], slept[i], slept)
		}
	}
}

func TestBuildVerifierWithRetry_ContextCancelAborts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	build := func() (callback.IDTokenVerifier, error) {
		calls++
		return nil, errors.New("down")
	}
	sleep := func(time.Duration) { t.Fatalf("sleep should not be called when context already cancelled") }

	got, err := buildVerifierWithRetry(ctx, retryKnobs{attempts: 5, base: time.Second, factor: 2, cap: time.Minute}, sleep, build)
	if err == nil {
		t.Fatalf("expected error on cancelled context")
	}
	if got != nil {
		t.Fatalf("expected nil verifier")
	}
	// With a pre-cancelled context the loop must check ctx BEFORE the first
	// build and bail out, so build is never called.
	if calls != 0 {
		t.Fatalf("expected 0 build attempts with a pre-cancelled context, got %d", calls)
	}
}

func TestProviderJWKSIsNotUsedForInboundBearerValidation(t *testing.T) {
	previous := defaultVerifierRetry
	defaultVerifierRetry = retryKnobs{attempts: 1}
	t.Cleanup(func() { defaultVerifierRetry = previous })

	p, err := NewOAuthProxy(&types.Config{
		Mode:                ModeForwardAuth,
		OAuthClientID:       "client",
		OAuthClientSecret:   "secret",
		OAuthAuthorizeURL:   "https://accounts.google.com",
		OAuthIssuerURL:      "https://accounts.google.com",
		OAuthJWKSURL:        "://invalid-provider-jwks-url",
		ScopesSupported:     "openid,email",
		AllowedEmailDomains: []string{"example.com"},
	})
	require.NoError(t, err)
	require.NoError(t, p.Close())
}

// captureLog runs fn with the standard logger redirected to a buffer and
// returns everything that was logged.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	prev := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prev)
		log.SetFlags(flags)
	}()
	fn()
	return buf.String()
}

// newVerifierTestProxy builds a bare OAuthProxy with only the fields the
// id_token verifier build path needs, avoiding any DB connection so these unit
// tests run fast and offline.
func newVerifierTestProxy(t *testing.T, cfg *types.Config) *OAuthProxy {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &OAuthProxy{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

func TestBuildIDTokenVerifier_NonOIDC_NoRetryNoWarning(t *testing.T) {
	p := newVerifierTestProxy(t, &types.Config{
		// No JWKS URL / issuer / client ID => MaybeNewVerifier returns (nil,nil).
		OAuthAuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
	})

	sleeps := 0
	p.idtokenSleep = func(time.Duration) { sleeps++ }

	out := captureLog(func() {
		v := p.buildIDTokenVerifier()
		if v != nil {
			t.Fatalf("expected nil verifier for non-OIDC setup")
		}
	})
	if sleeps != 0 {
		t.Fatalf("expected zero sleeps for non-OIDC setup, got %d", sleeps)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("expected no log output for non-OIDC setup, got: %q", out)
	}
}

func TestBuildIDTokenVerifier_Exhausted_WarnsDisabled(t *testing.T) {
	p := newVerifierTestProxy(t, &types.Config{
		OAuthAuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		OAuthJWKSURL:      "https://accounts.google.com/jwks-unreachable",
		OAuthClientID:     "client-123",
	})
	p.idtokenSleep = func(time.Duration) {}
	// Force the build to always fail without hitting the network.
	p.idtokenBuild = func() (callback.IDTokenVerifier, error) {
		return nil, errors.New("JWKS endpoint unreachable")
	}

	var v callback.IDTokenVerifier
	out := captureLog(func() { v = p.buildIDTokenVerifier() })
	if v != nil {
		t.Fatalf("expected nil verifier after exhausting retries")
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "warning") || !strings.Contains(lower, "id_token verification") || !strings.Contains(lower, "disabled") {
		t.Fatalf("expected a WARNING that id_token verification is DISABLED, got: %q", out)
	}
}

func TestBuildIDTokenVerifier_DerivedIssuerWarning(t *testing.T) {
	build := func() (callback.IDTokenVerifier, error) { return okVerifier{}, nil }

	t.Run("derived issuer (no OAUTH_ISSUER_URL) warns", func(t *testing.T) {
		p := newVerifierTestProxy(t, &types.Config{
			OAuthAuthorizeURL: "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
			OAuthJWKSURL:      "https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
			OAuthClientID:     "client-123",
			// OAuthIssuerURL deliberately empty => issuer derived.
		})
		p.idtokenSleep = func(time.Duration) {}
		p.idtokenBuild = build

		var v callback.IDTokenVerifier
		out := captureLog(func() { v = p.buildIDTokenVerifier() })
		if v == nil {
			t.Fatalf("expected a verifier to be built")
		}
		lower := strings.ToLower(out)
		if !strings.Contains(lower, "derived") || !strings.Contains(lower, "oauth_issuer_url") {
			t.Fatalf("expected a derived-issuer WARNING mentioning OAUTH_ISSUER_URL, got: %q", out)
		}
	})

	t.Run("explicit OAUTH_ISSUER_URL does not warn", func(t *testing.T) {
		p := newVerifierTestProxy(t, &types.Config{
			OAuthAuthorizeURL: "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
			OAuthJWKSURL:      "https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
			OAuthClientID:     "client-123",
			OAuthIssuerURL:    "https://login.microsoftonline.com/tenant/v2.0",
		})
		p.idtokenSleep = func(time.Duration) {}
		p.idtokenBuild = build

		var v callback.IDTokenVerifier
		out := captureLog(func() { v = p.buildIDTokenVerifier() })
		if v == nil {
			t.Fatalf("expected a verifier to be built")
		}
		if strings.Contains(strings.ToLower(out), "derived") {
			t.Fatalf("expected NO derived-issuer warning when OAUTH_ISSUER_URL is set, got: %q", out)
		}
	})
}

// TestBuildIDTokenVerifier_NilVerifierNilErrWithParams_WarnsDisabled covers the
// defensive path where OIDC params ARE present but the build returns
// (nil, nil). The closure must convert that into an error so the retry loop
// retries and, on exhaustion, emits the DISABLED warning rather than silently
// returning nil as if it were success.
func TestBuildIDTokenVerifier_NilVerifierNilErrWithParams_WarnsDisabled(t *testing.T) {
	p := newVerifierTestProxy(t, &types.Config{
		OAuthAuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		OAuthJWKSURL:      "https://accounts.google.com/jwks-unreachable",
		OAuthClientID:     "client-123",
	})

	sleeps := 0
	p.idtokenSleep = func(time.Duration) { sleeps++ }
	calls := 0
	// Always return (nil, nil) despite params being present.
	p.idtokenBuild = func() (callback.IDTokenVerifier, error) {
		calls++
		return nil, nil
	}

	var v callback.IDTokenVerifier
	out := captureLog(func() { v = p.buildIDTokenVerifier() })
	if v != nil {
		t.Fatalf("expected nil verifier")
	}
	// It must have retried (more than one attempt) rather than treating the
	// first (nil,nil) as success.
	if calls <= 1 {
		t.Fatalf("expected the loop to retry on (nil,nil) with params present, got %d build calls", calls)
	}
	if sleeps == 0 {
		t.Fatalf("expected backoff sleeps between retries, got 0")
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "warning") || !strings.Contains(lower, "id_token verification") || !strings.Contains(lower, "disabled") {
		t.Fatalf("expected a WARNING that id_token verification is DISABLED, got: %q", out)
	}
}

// TestBuildIDTokenVerifier_RealUnreachableJWKS_RetriesThenWarns proves the
// end-to-end fix: with NO idtokenBuild seam, a real (refused) JWKS URL makes the
// genuine idtoken.MaybeNewVerifier path return an error, which the retry loop
// retries (multiple sleeps) and then degrades with the DISABLED warning. A fake
// sleeper keeps it fast; a short HTTPClient timeout is implicit via the dead
// port (connection refused returns immediately).
func TestBuildIDTokenVerifier_RealUnreachableJWKS_RetriesThenWarns(t *testing.T) {
	// Bind then close a listener so the port is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadURL := "http://" + ln.Addr().String() + "/jwks"
	_ = ln.Close()

	p := newVerifierTestProxy(t, &types.Config{
		OAuthAuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		OAuthJWKSURL:      deadURL,
		OAuthClientID:     "client-123",
	})

	sleeps := 0
	p.idtokenSleep = func(time.Duration) { sleeps++ }
	// Deliberately leave p.idtokenBuild nil so the real MaybeNewVerifier path
	// runs and must surface the unreachable-JWKS error.

	var v callback.IDTokenVerifier
	out := captureLog(func() { v = p.buildIDTokenVerifier() })
	if v != nil {
		t.Fatalf("expected nil verifier for an unreachable JWKS endpoint")
	}
	// defaultVerifierRetry uses 5 attempts => 4 sleeps between them. The key
	// assertion is that retries actually happened (the whole point of the fix).
	if sleeps == 0 {
		t.Fatalf("expected the retry loop to sleep between attempts on a real unreachable JWKS, got 0 sleeps")
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "warning") || !strings.Contains(lower, "id_token verification") || !strings.Contains(lower, "disabled") {
		t.Fatalf("expected a WARNING that id_token verification is DISABLED after retries, got: %q", out)
	}
}

// TestBuildVerifierWithRetry_ContextCancelDuringWaitAborts proves the wait
// between attempts is abortable: cancelling the context WHILE the backoff sleep
// is in progress makes the loop return promptly with ctx.Err rather than
// blocking for the full backoff. A long sleeper would hang the test if the wait
// were not racing ctx.Done.
func TestBuildVerifierWithRetry_ContextCancelDuringWaitAborts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	calls := 0
	build := func() (callback.IDTokenVerifier, error) {
		calls++
		return nil, errors.New("down")
	}

	// The sleeper blocks long enough that, if the wait were NOT abortable, the
	// test would exceed its deadline. We cancel from inside the sleeper to
	// simulate a shutdown arriving during the wait.
	sleep := func(time.Duration) {
		cancel()
		time.Sleep(2 * time.Second) // would dominate if the wait were not racing ctx.
	}

	start := time.Now()
	got, err := buildVerifierWithRetry(ctx, retryKnobs{
		attempts: 5,
		base:     time.Hour, // huge backoff; only abortability keeps this fast.
		factor:   2,
		cap:      time.Hour,
	}, sleep, build)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected ctx cancellation error")
	}
	if got != nil {
		t.Fatalf("expected nil verifier")
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 build before the wait was aborted, got %d", calls)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("expected prompt abort during the wait, took %v", elapsed)
	}
}
