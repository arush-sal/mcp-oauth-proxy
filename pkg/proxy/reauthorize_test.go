package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/authz"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/idtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// stubVerifier is a test double for callback.IDTokenVerifier.
type stubVerifier struct {
	claims *idtoken.Claims
	err    error
}

func (v *stubVerifier) Verify(context.Context, string) (*idtoken.Claims, error) {
	return v.claims, v.err
}

func storedPropsWithClaims(t *testing.T, claims idtoken.Claims) map[string]any {
	t.Helper()
	b, err := json.Marshal(&claims)
	require.NoError(t, err)
	return map[string]any{"id_token_claims": string(b)}
}

func newProxyWithAuthz(t *testing.T, cfg authz.Config, v *stubVerifier) *OAuthProxy {
	t.Helper()
	a, err := authz.New(cfg)
	require.NoError(t, err)
	p := &OAuthProxy{authorizer: a}
	if v != nil {
		p.idTokenVerifier = v
	}
	return p
}

func TestReauthorizeOnRefresh_StillMatching_NoFreshIDToken(t *testing.T) {
	p := newProxyWithAuthz(t, authz.Config{EmailDomains: []string{"example.com"}}, nil)
	old := storedPropsWithClaims(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})

	newProps, err := p.reauthorizeOnRefresh(context.Background(), old, &oauth2.Token{AccessToken: "at"})
	require.NoError(t, err)
	assert.Equal(t, old["id_token_claims"], newProps["id_token_claims"])
}

func TestReauthorizeOnRefresh_NoLongerMatching(t *testing.T) {
	p := newProxyWithAuthz(t, authz.Config{EmailDomains: []string{"example.com"}}, nil)
	old := storedPropsWithClaims(t, idtoken.Claims{Email: "user@removed.com", EmailVerified: true})

	_, err := p.reauthorizeOnRefresh(context.Background(), old, &oauth2.Token{AccessToken: "at"})
	assert.ErrorIs(t, err, authz.ErrDenied)
}

func TestReauthorizeOnRefresh_FreshIDTokenUpdatesClaimsAndAllows(t *testing.T) {
	// Old stored claims are out of date (denied); a fresh id_token brings the
	// user back into the allowlist and the stored claims are refreshed.
	v := &stubVerifier{claims: &idtoken.Claims{Email: "user@example.com", EmailVerified: true}}
	p := newProxyWithAuthz(t, authz.Config{EmailDomains: []string{"example.com"}}, v)

	old := storedPropsWithClaims(t, idtoken.Claims{Email: "user@removed.com", EmailVerified: true})
	newTok := (&oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": "fresh-id-token"})

	newProps, err := p.reauthorizeOnRefresh(context.Background(), old, newTok)
	require.NoError(t, err)

	var claims idtoken.Claims
	require.NoError(t, json.Unmarshal([]byte(newProps["id_token_claims"].(string)), &claims))
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, "fresh-id-token", newProps["id_token"])
}

func TestReauthorizeOnRefresh_FreshIDTokenInvalidFailsClosed(t *testing.T) {
	v := &stubVerifier{err: errors.New("bad signature")}
	p := newProxyWithAuthz(t, authz.Config{EmailDomains: []string{"example.com"}}, v)

	old := storedPropsWithClaims(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	newTok := (&oauth2.Token{AccessToken: "at"}).
		WithExtra(map[string]any{"id_token": "fresh-id-token"})

	_, err := p.reauthorizeOnRefresh(context.Background(), old, newTok)
	require.Error(t, err)
}

func TestReauthorizeOnRefresh_NilAuthorizerDenies(t *testing.T) {
	// CONCERN 1: a nil authorizer must fail closed (deny), not allow.
	p := &OAuthProxy{authorizer: nil}
	old := storedPropsWithClaims(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})

	_, err := p.reauthorizeOnRefresh(context.Background(), old, &oauth2.Token{AccessToken: "at"})
	require.Error(t, err)
	assert.ErrorIs(t, err, authz.ErrDenied)
}

func TestReauthorizeOnRefresh_DenyReturnsErrDenied(t *testing.T) {
	// CONCERN 2 (deny side): an authorization deny is classifiable as ErrDenied
	// so the caller revokes the session.
	p := newProxyWithAuthz(t, authz.Config{EmailDomains: []string{"example.com"}}, nil)
	old := storedPropsWithClaims(t, idtoken.Claims{Email: "user@removed.com", EmailVerified: true})

	_, err := p.reauthorizeOnRefresh(context.Background(), old, &oauth2.Token{AccessToken: "at"})
	assert.ErrorIs(t, err, authz.ErrDenied)
}

func TestReauthorizeOnRefresh_InvalidIDTokenIsNotErrDenied(t *testing.T) {
	// CONCERN 2 (infra side): a verifier failure is an infrastructure error, not
	// an authorization deny, so it must NOT be classified as ErrDenied (caller
	// must not destroy the session on a transient verify failure).
	v := &stubVerifier{err: errors.New("jwks unreachable")}
	p := newProxyWithAuthz(t, authz.Config{EmailDomains: []string{"example.com"}}, v)

	old := storedPropsWithClaims(t, idtoken.Claims{Email: "user@example.com", EmailVerified: true})
	newTok := (&oauth2.Token{AccessToken: "at"}).WithExtra(map[string]any{"id_token": "fresh"})

	_, err := p.reauthorizeOnRefresh(context.Background(), old, newTok)
	require.Error(t, err)
	assert.NotErrorIs(t, err, authz.ErrDenied, "infra error must not be an authorization deny")
}

func TestReauthorizeOnRefresh_DoesNotMutateInput(t *testing.T) {
	v := &stubVerifier{claims: &idtoken.Claims{Email: "user@example.com", EmailVerified: true}}
	p := newProxyWithAuthz(t, authz.Config{EmailDomains: []string{"example.com"}}, v)

	old := storedPropsWithClaims(t, idtoken.Claims{Email: "user@removed.com", EmailVerified: true})
	origClaims := old["id_token_claims"]
	newTok := (&oauth2.Token{AccessToken: "at"}).WithExtra(map[string]any{"id_token": "fresh"})

	_, err := p.reauthorizeOnRefresh(context.Background(), old, newTok)
	require.NoError(t, err)
	assert.Equal(t, origClaims, old["id_token_claims"], "input props must not be mutated")
}
