package types

import (
	"net/http"
	"testing"
	"time"
)

func TestResolveSessionConfig_Defaults(t *testing.T) {
	sc, err := ResolveSessionConfig(&Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.AccessTTL != time.Hour {
		t.Errorf("AccessTTL = %v, want 1h", sc.AccessTTL)
	}
	if sc.RefreshTTL != 720*time.Hour {
		t.Errorf("RefreshTTL = %v, want 720h", sc.RefreshTTL)
	}
	if sc.CookieSecure != CookieSecureAuto {
		t.Errorf("CookieSecure = %v, want auto", sc.CookieSecure)
	}
	if sc.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", sc.SameSite)
	}
}

func TestResolveSessionConfig_DefaultsReproduceLegacySeconds(t *testing.T) {
	sc, err := ResolveSessionConfig(&Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := int(sc.AccessTTL.Seconds()); got != 3600 {
		t.Errorf("AccessTTL seconds = %d, want 3600", got)
	}
	if got := int(sc.RefreshTTL.Seconds()); got != 2592000 {
		t.Errorf("RefreshTTL seconds = %d, want 2592000", got)
	}
}

func TestResolveSessionConfig_CustomDurations(t *testing.T) {
	sc, err := ResolveSessionConfig(&Config{CookieExpire: "30m", CookieRefresh: "2h"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.AccessTTL != 30*time.Minute {
		t.Errorf("AccessTTL = %v, want 30m", sc.AccessTTL)
	}
	if sc.RefreshTTL != 2*time.Hour {
		t.Errorf("RefreshTTL = %v, want 2h", sc.RefreshTTL)
	}
}

func TestResolveSessionConfig_SameSiteModes(t *testing.T) {
	cases := map[string]http.SameSite{
		"lax":    http.SameSiteLaxMode,
		"strict": http.SameSiteStrictMode,
		"none":   http.SameSiteNoneMode,
		"LAX":    http.SameSiteLaxMode,
	}
	for in, want := range cases {
		cfg := &Config{CookieSameSite: in}
		if in == "none" || in == "NONE" {
			cfg.CookieSecure = "true"
		}
		sc, err := ResolveSessionConfig(cfg)
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", in, err)
		}
		if sc.SameSite != want {
			t.Errorf("%q: SameSite = %v, want %v", in, sc.SameSite, want)
		}
	}
}

func TestResolveSessionConfig_SecureModes(t *testing.T) {
	cases := map[string]CookieSecureMode{
		"auto":  CookieSecureAuto,
		"true":  CookieSecureAlways,
		"false": CookieSecureNever,
		"AUTO":  CookieSecureAuto,
	}
	for in, want := range cases {
		sc, err := ResolveSessionConfig(&Config{CookieSecure: in})
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", in, err)
		}
		if sc.CookieSecure != want {
			t.Errorf("%q: CookieSecure = %v, want %v", in, sc.CookieSecure, want)
		}
	}
}

func TestResolveSessionConfig_InvalidSameSite(t *testing.T) {
	_, err := ResolveSessionConfig(&Config{CookieSameSite: "bogus"})
	if err == nil {
		t.Fatal("expected error for invalid COOKIE_SAMESITE")
	}
}

func TestResolveSessionConfig_InvalidSecure(t *testing.T) {
	_, err := ResolveSessionConfig(&Config{CookieSecure: "bogus"})
	if err == nil {
		t.Fatal("expected error for invalid COOKIE_SECURE")
	}
}

func TestResolveSessionConfig_NoneRequiresSecure(t *testing.T) {
	_, err := ResolveSessionConfig(&Config{CookieSameSite: "none", CookieSecure: "false"})
	if err == nil {
		t.Fatal("expected error: SameSite=None requires Secure")
	}
}

func TestResolveSessionConfig_NoneWithAutoRejected(t *testing.T) {
	// auto cannot guarantee Secure, so none+auto must be rejected.
	_, err := ResolveSessionConfig(&Config{CookieSameSite: "none"})
	if err == nil {
		t.Fatal("expected error: SameSite=None requires Secure (auto is not guaranteed)")
	}
}

func TestResolveSessionConfig_NonPositiveDurations(t *testing.T) {
	if _, err := ResolveSessionConfig(&Config{CookieExpire: "0"}); err == nil {
		t.Error("expected error for zero COOKIE_EXPIRE")
	}
	if _, err := ResolveSessionConfig(&Config{CookieExpire: "-5m"}); err == nil {
		t.Error("expected error for negative COOKIE_EXPIRE")
	}
	if _, err := ResolveSessionConfig(&Config{CookieRefresh: "0s"}); err == nil {
		t.Error("expected error for zero COOKIE_REFRESH")
	}
	if _, err := ResolveSessionConfig(&Config{CookieRefresh: "-1h"}); err == nil {
		t.Error("expected error for negative COOKIE_REFRESH")
	}
}

func TestResolveSessionConfig_SubSecondDurationsRejected(t *testing.T) {
	// Sub-second durations are > 0 (so they pass a naive d>0 check) but truncate
	// to 0 whole seconds, which would yield a session cookie (MaxAge:0) and a DB
	// ExpiresAt in the past. They must be rejected with a minimum-1s floor.
	if _, err := ResolveSessionConfig(&Config{CookieExpire: "500ms"}); err == nil {
		t.Error("expected error for sub-second COOKIE_EXPIRE (500ms)")
	}
	if _, err := ResolveSessionConfig(&Config{CookieRefresh: "500ms"}); err == nil {
		t.Error("expected error for sub-second COOKIE_REFRESH (500ms)")
	}
	// Exactly 1s is the floor and must be accepted.
	sc, err := ResolveSessionConfig(&Config{CookieExpire: "1s", CookieRefresh: "1s"})
	if err != nil {
		t.Fatalf("1s must be accepted, got error: %v", err)
	}
	if sc.AccessTTL != time.Second {
		t.Errorf("AccessTTL = %v, want 1s", sc.AccessTTL)
	}
	if sc.RefreshTTL != time.Second {
		t.Errorf("RefreshTTL = %v, want 1s", sc.RefreshTTL)
	}
}

func TestResolveSessionConfig_InvalidDurationString(t *testing.T) {
	if _, err := ResolveSessionConfig(&Config{CookieExpire: "abc"}); err == nil {
		t.Error("expected error for unparseable COOKIE_EXPIRE")
	}
	if _, err := ResolveSessionConfig(&Config{CookieRefresh: "5"}); err == nil {
		// "5" has no unit; time.ParseDuration rejects it (except "0").
		t.Error("expected error for unitless COOKIE_REFRESH")
	}
}

func TestSessionConfig_SecureFor(t *testing.T) {
	httpsReq := httptest_NewRequest(true)
	httpReq := httptest_NewRequest(false)

	auto := SessionConfig{CookieSecure: CookieSecureAuto}
	if !auto.SecureForRequest(httpsReq) {
		t.Error("auto: expected Secure on HTTPS request")
	}
	if auto.SecureForRequest(httpReq) {
		t.Error("auto: expected not Secure on plain HTTP request")
	}

	always := SessionConfig{CookieSecure: CookieSecureAlways}
	if !always.SecureForRequest(httpReq) {
		t.Error("always: expected Secure even on plain HTTP")
	}

	never := SessionConfig{CookieSecure: CookieSecureNever}
	if never.SecureForRequest(httpsReq) {
		t.Error("never: expected not Secure even on HTTPS")
	}
}

// httptest_NewRequest builds a request whose "secure" signal matches the
// existing isSecureRequest semantics (TLS set OR X-Forwarded-Proto: https).
func httptest_NewRequest(secure bool) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if secure {
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	return r
}
