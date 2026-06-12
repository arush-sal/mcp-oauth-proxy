// Package authz implements the proxy's authorization (allowlist) decision: it
// decides WHO, among already-authenticated users, may use the proxy. It mirrors
// oauth2-proxy's allowlist semantics, the most important of which is fail-closed
// DENY-ALL by default.
//
// IMPORTANT BREAKING CHANGE: a zero-config Authorizer denies EVERY user. This is
// deliberate parity with oauth2-proxy: you must explicitly opt in to who is
// allowed. To restore the old "any authenticated user" behavior, set the email
// domain allowlist to the single wildcard value "*".
//
// The matcher is pure and side-effect free so it can be exhaustively table
// tested. Identity attributes are supplied by the caller (sourced from a
// verified IdP id_token, with a userinfo fallback); this package never fetches
// anything.
package authz

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrDenied is the sentinel error returned by Authorize when the identity does
// not match any configured allow rule (including the zero-config deny-all
// default). Callers should map it to a 403 / access_denied.
var ErrDenied = errors.New("authz: access denied")

// Identity is the set of already-verified attributes an authorization decision
// is made against. It is derived from the IdP id_token claims first, with a
// userinfo fallback for attributes a configured rule needs but the id_token
// lacks.
type Identity struct {
	// Subject is the IdP "sub" claim. Used only to recognise that a request is
	// authenticated at all (for the "*" wildcard escape hatch).
	Subject string
	// Email is the user's email address.
	Email string
	// EmailVerified reports whether the IdP asserts the email is verified. An
	// unverified email MUST NOT satisfy an email or email-domain rule.
	EmailVerified bool
	// Groups is the user's group membership from the configured groups claim.
	Groups []string
	// HostedDomain is the Google "hd" (hosted domain) claim.
	HostedDomain string
}

// Config holds the raw allowlist inputs, typically sourced from environment
// variables. The emails file is expected to already be loaded and merged into
// Emails by the caller (see LoadEmailsFile).
type Config struct {
	// Emails is the list of explicitly allowed email addresses (case-insensitive).
	Emails []string
	// EmailDomains is the list of allowed email domains (the part after "@").
	// The special single value "*" allows ANY authenticated user.
	EmailDomains []string
	// Groups is the list of allowed groups; a user is allowed if their groups
	// intersect this list.
	Groups []string
	// GoogleHostedDomains is the list of allowed Google hosted domains, matched
	// against the "hd" claim.
	GoogleHostedDomains []string
}

// Authorizer holds precomputed, normalized allow rules and renders a fail-closed
// allow/deny decision for an Identity.
type Authorizer struct {
	emails       map[string]struct{}
	emailDomains map[string]struct{}
	groups       map[string]struct{}
	hostedDomain map[string]struct{}

	// allowAny is true when EmailDomains contains the "*" wildcard, restoring
	// the legacy "any authenticated user" behavior.
	allowAny bool
}

// New builds an Authorizer from cfg, precomputing lowercased lookup sets and
// detecting the "*" wildcard email domain. A zero-config Authorizer is valid and
// denies everything.
func New(cfg Config) (*Authorizer, error) {
	a := &Authorizer{
		emails:       map[string]struct{}{},
		emailDomains: map[string]struct{}{},
		groups:       map[string]struct{}{},
		hostedDomain: map[string]struct{}{},
	}

	for _, e := range cfg.Emails {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			a.emails[e] = struct{}{}
		}
	}
	for _, d := range cfg.EmailDomains {
		d = strings.TrimSpace(d)
		if d == "*" {
			a.allowAny = true
			continue
		}
		d = strings.ToLower(d)
		if d != "" {
			a.emailDomains[d] = struct{}{}
		}
	}
	for _, g := range cfg.Groups {
		g = strings.TrimSpace(g)
		if g != "" {
			a.groups[g] = struct{}{}
		}
	}
	for _, h := range cfg.GoogleHostedDomains {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			a.hostedDomain[h] = struct{}{}
		}
	}

	return a, nil
}

// Enabled reports whether any allow rule is configured. It is informational
// only: it does NOT change the decision. A disabled (zero-config) authorizer
// still denies every request via Authorize.
func (a *Authorizer) Enabled() bool {
	return a.allowAny ||
		len(a.emails) > 0 ||
		len(a.emailDomains) > 0 ||
		len(a.groups) > 0 ||
		len(a.hostedDomain) > 0
}

// Authorize returns nil if id matches at least one configured allow rule, and
// ErrDenied otherwise. Decision order (all rules OR together; first match wins):
//  1. "*" email-domain wildcard -> allow any authenticated user.
//  2. email in the allowed emails set (case-insensitive; requires EmailVerified).
//  3. email's domain in the allowed domains set (case-insensitive; requires EmailVerified).
//  4. user's groups intersect the allowed groups.
//  5. hosted domain ("hd") in the allowed Google hosted domains (requires EmailVerified).
//
// With no rules configured, none of the above can match, so the zero-config
// authorizer denies everything (fail-closed default).
func (a *Authorizer) Authorize(id Identity) error {
	if a.allowAny {
		return nil
	}

	// Email / email-domain rules require a verified email.
	if id.EmailVerified && id.Email != "" {
		email := strings.ToLower(strings.TrimSpace(id.Email))
		if len(a.emails) > 0 {
			if _, ok := a.emails[email]; ok {
				return nil
			}
		}
		if len(a.emailDomains) > 0 {
			if at := strings.LastIndex(email, "@"); at >= 0 && at < len(email)-1 {
				domain := email[at+1:]
				if _, ok := a.emailDomains[domain]; ok {
					return nil
				}
			}
		}
	}

	if len(a.groups) > 0 {
		for _, g := range id.Groups {
			if _, ok := a.groups[strings.TrimSpace(g)]; ok {
				return nil
			}
		}
	}

	// The Google hosted-domain rule, like the email/domain rules, requires a
	// verified email: a source populating "hd" for an unverified account must
	// not be authorized.
	if id.EmailVerified && len(a.hostedDomain) > 0 && id.HostedDomain != "" {
		if _, ok := a.hostedDomain[strings.ToLower(strings.TrimSpace(id.HostedDomain))]; ok {
			return nil
		}
	}

	return ErrDenied
}

// NeedsEmail reports whether any configured rule needs the email attribute (an
// email or email-domain rule). The "*" wildcard needs nothing.
func (a *Authorizer) NeedsEmail() bool {
	if a.allowAny {
		return false
	}
	return len(a.emails) > 0 || len(a.emailDomains) > 0
}

// NeedsGroups reports whether a group rule is configured.
func (a *Authorizer) NeedsGroups() bool {
	if a.allowAny {
		return false
	}
	return len(a.groups) > 0
}

// NeedsHostedDomain reports whether a Google hosted-domain rule is configured.
func (a *Authorizer) NeedsHostedDomain() bool {
	if a.allowAny {
		return false
	}
	return len(a.hostedDomain) > 0
}

// LoadEmailsFile reads an allowed-emails file: one email per line, with blank
// lines and lines starting with "#" ignored. Each remaining line is trimmed of
// surrounding whitespace. Case is preserved here (New lowercases for matching).
// A missing or unreadable file returns an error so misconfiguration fails loudly
// at construction time.
func LoadEmailsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("authz: failed to open emails file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var emails []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		emails = append(emails, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("authz: failed to read emails file %q: %w", path, err)
	}
	return emails, nil
}
