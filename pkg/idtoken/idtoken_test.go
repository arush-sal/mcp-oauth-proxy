package idtoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer   = "https://idp.example.com"
	testAudience = "test-client-id"
	testKID      = "test-key-1"
)

// newTestKey generates an RSA key pair for signing test id_tokens.
func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// jwksJSON builds a minimal JWKS document exposing the public half of key.
func jwksJSON(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	pub := key.Public().(*rsa.PublicKey)
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	doc := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kid,
				"n":   n,
				"e":   e,
			},
		},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	return b
}

// jwksServer serves the JWKS document over HTTP for the verifier to fetch.
func jwksServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	body := jwksJSON(t, key, kid)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// signToken signs claims into a JWT using key and the given kid/alg.
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

func baseClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":            testIssuer,
		"aud":            testAudience,
		"sub":            "user-123",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	}
}

func newTestVerifier(t *testing.T, jwksURL string) *Verifier {
	t.Helper()
	v, err := NewVerifier(context.Background(), Config{
		Issuer:   testIssuer,
		JWKSURL:  jwksURL,
		Audience: testAudience,
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	return v
}

func TestVerify_ValidToken(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, baseClaims())

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, "user-123", claims.Subject)
	assert.Empty(t, claims.Groups)
	assert.Empty(t, claims.HostedDomain)
}

func TestVerify_PopulatesExpiresAt(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	exp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	c := baseClaims()
	c["exp"] = exp.Unix()
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, exp.Unix(), claims.ExpiresAt)
}

func TestVerify_WrongAudience(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["aud"] = "some-other-client"
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	_, err := v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_WrongIssuer(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["iss"] = "https://evil.example.com"
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	_, err := v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_Expired(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	c["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	_, err := v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_BadSignature(t *testing.T) {
	signingKey := newTestKey(t)
	otherKey := newTestKey(t)
	// JWKS advertises otherKey's public half under testKID, but the token is
	// signed with signingKey, so signature verification must fail.
	srv := jwksServer(t, otherKey, testKID)
	v := newTestVerifier(t, srv.URL)

	raw := signToken(t, signingKey, testKID, jwt.SigningMethodRS256, baseClaims())

	_, err := v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_GroupsAsArray(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["groups"] = []string{"a", "b"}
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, claims.Groups)
}

func TestVerify_GroupsAsString(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["groups"] = "a"
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, claims.Groups)
}

func TestVerify_HostedDomain(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["hd"] = "example.com"
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "example.com", claims.HostedDomain)
}

func TestVerify_MissingOptionalClaims(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, baseClaims())

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Empty(t, claims.Groups)
	assert.Empty(t, claims.HostedDomain)
}

func TestVerify_EmptyTokenIsError(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	_, err := v.Verify(context.Background(), "")
	require.Error(t, err)
}

func TestVerify_ConfigurableGroupsClaim(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v, err := NewVerifier(context.Background(), Config{
		Issuer:      testIssuer,
		JWKSURL:     srv.URL,
		Audience:    testAudience,
		GroupsClaim: "roles",
	})
	require.NoError(t, err)

	c := baseClaims()
	// The non-standard claim name carries the groups; the standard "groups"
	// claim is present but must be ignored when GroupsClaim is configured.
	c["roles"] = []string{"x", "y"}
	c["groups"] = []string{"ignored"}
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, []string{"x", "y"}, claims.Groups)
}

func TestVerify_ConfigurableGroupsClaim_String(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v, err := NewVerifier(context.Background(), Config{
		Issuer:      testIssuer,
		JWKSURL:     srv.URL,
		Audience:    testAudience,
		GroupsClaim: "roles",
	})
	require.NoError(t, err)

	c := baseClaims()
	c["roles"] = "solo"
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, []string{"solo"}, claims.Groups)
}

func TestVerify_DefaultGroupsClaimUnchanged(t *testing.T) {
	// With no GroupsClaim configured, the standard "groups" claim is still used.
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["groups"] = []string{"g1"}
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, []string{"g1"}, claims.Groups)
}

func TestVerify_RejectsAlgNone(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	// Build an unsigned ("alg":"none") token manually.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
	tok.Header["kid"] = testKID
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_RejectsHMACSignedToken(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	// An attacker-controlled HMAC token must be rejected: HS256 is not in the
	// verifier's allowed methods.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
	tok.Header["kid"] = testKID
	raw, err := tok.SignedString([]byte("shared-secret"))
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_NullGroupsYieldsEmpty(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["groups"] = nil
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Empty(t, claims.Groups)
}

func TestVerify_MixedTypeGroupsArrayRejected(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["groups"] = []any{"a", 1}
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	_, err := v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_ArrayAudienceAccepted(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	// aud as a JSON array that includes the expected audience. Per OIDC Core
	// 3.1.3.7, a multi-valued aud requires azp == client ID.
	c["aud"] = []string{"other-client", testAudience}
	c["azp"] = testAudience
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Email)
}

func TestVerify_SingleAudNoAzpAccepted(t *testing.T) {
	// Single-valued aud == clientID with no azp is accepted (azp optional).
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims() // aud is the single testAudience, no azp
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Email)
}

func TestVerify_MultiAudWithMatchingAzpAccepted(t *testing.T) {
	// Multi-valued aud containing clientID with azp == clientID is accepted.
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["aud"] = []string{"other-client", testAudience}
	c["azp"] = testAudience
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Email)
}

func TestVerify_MultiAudWithWrongAzpRejected(t *testing.T) {
	// Multi-valued aud containing clientID but azp == other party is rejected
	// (OIDC Core 3.1.3.7).
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["aud"] = []string{"other-client", testAudience}
	c["azp"] = "other-client"
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	_, err := v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_MultiAudWithoutAzpRejected(t *testing.T) {
	// Multi-valued aud containing clientID with azp absent is rejected: when aud
	// is multi-valued, azp MUST be present and equal to the client ID.
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["aud"] = []string{"other-client", testAudience}
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	_, err := v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_MultiAudNotContainingClientIDRejected(t *testing.T) {
	// aud not containing clientID is rejected by the audience membership check,
	// regardless of azp.
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)
	v := newTestVerifier(t, srv.URL)

	c := baseClaims()
	c["aud"] = []string{"other-client", "yet-another"}
	c["azp"] = testAudience
	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, c)

	_, err := v.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestClaims_UnmarshalGroups(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "array", raw: `{"groups":["a","b"]}`, want: []string{"a", "b"}},
		{name: "string", raw: `{"groups":"a"}`, want: []string{"a"}},
		{name: "absent", raw: `{}`, want: nil},
		{name: "empty string", raw: `{"groups":""}`, want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c Claims
			require.NoError(t, json.Unmarshal([]byte(tc.raw), &c))
			assert.Equal(t, tc.want, c.Groups)
		})
	}
}

// TestNewVerifier_UnreachableJWKS_ReturnsError asserts that when the JWKS
// endpoint is unreachable/failing at construction time, NewVerifier surfaces a
// non-nil ERROR (rather than a nil-error verifier with an empty key cache).
// This is what lets the proxy's startup retry loop actually retry. See the
// keyfunc/jwkset NoErrorReturnFirstHTTPReq behavior.
func TestNewVerifier_UnreachableJWKS_ReturnsError(t *testing.T) {
	t.Run("500 response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		v, err := NewVerifier(context.Background(), Config{
			Issuer:   testIssuer,
			JWKSURL:  srv.URL,
			Audience: testAudience,
		})
		require.Error(t, err, "expected an error when the JWKS endpoint returns 500")
		require.Nil(t, v, "verifier must be nil when the initial JWKS fetch fails")
	})

	t.Run("connection refused", func(t *testing.T) {
		// Bind a listener then close it so the port is (almost certainly) refused.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		url := "http://" + ln.Addr().String() + "/jwks"
		require.NoError(t, ln.Close())

		// Bound the client so a hung/refused endpoint cannot block boot.
		v, err := NewVerifier(context.Background(), Config{
			Issuer:     testIssuer,
			JWKSURL:    url,
			Audience:   testAudience,
			HTTPClient: &http.Client{Timeout: 2 * time.Second},
		})
		require.Error(t, err, "expected an error when the JWKS endpoint is unreachable")
		require.Nil(t, v)
	})
}

// TestMaybeNewVerifier_UnreachableJWKS_ReturnsError mirrors the above through
// MaybeNewVerifier (params present), which is the entry point the proxy uses.
func TestMaybeNewVerifier_UnreachableJWKS_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	v, err := MaybeNewVerifier(context.Background(), Config{
		Issuer:   testIssuer,
		JWKSURL:  srv.URL,
		Audience: testAudience,
	})
	require.Error(t, err)
	require.Nil(t, v)
}

// TestNewVerifier_ReachableJWKS_HappyPath confirms that when JWKS IS reachable
// the verifier is built successfully (first fetch succeeds) and can verify a
// token, i.e. surfacing the initial-fetch error did not break the happy path.
func TestNewVerifier_ReachableJWKS_HappyPath(t *testing.T) {
	key := newTestKey(t)
	srv := jwksServer(t, key, testKID)

	v, err := NewVerifier(context.Background(), Config{
		Issuer:   testIssuer,
		JWKSURL:  srv.URL,
		Audience: testAudience,
	})
	require.NoError(t, err)
	require.NotNil(t, v)

	raw := signToken(t, key, testKID, jwt.SigningMethodRS256, baseClaims())
	claims, err := v.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Email)
}
