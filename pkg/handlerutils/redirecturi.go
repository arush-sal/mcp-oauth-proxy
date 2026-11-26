package handlerutils

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// RedirectURIMatches reports whether requested matches one of a client's
// registered redirect URIs.
//
// The default is an exact string match. The one exception is RFC 8252 section
// 7.3: for a loopback IP redirect the authorization server MUST allow any port.
// So when a registered URI uses the http scheme with a loopback host
// (127.0.0.1, [::1] or localhost), requested matches it if the scheme, host,
// path and query are identical and only the port differs. Native apps such as
// Claude Code reuse a cached client_id but bind a new random loopback port on
// each sign-in, which an exact match would reject.
//
// Only the port is relaxed, and only for http loopback. The scheme, host, path
// and query must still match exactly, so this never accepts a different host, a
// different path, an http->https downgrade, or a non-loopback host. https
// loopback is NOT relaxed (RFC 8252 covers http loopback only).
func RedirectURIMatches(registered []string, requested string) bool {
	if requested == "" {
		return false
	}
	if slices.Contains(registered, requested) {
		return true
	}

	req, err := url.Parse(requested)
	if err != nil || strings.ToLower(req.Scheme) != "http" || !isLoopbackHost(req.Hostname()) {
		return false
	}
	// Reject embedded credentials and fragments on the requested URI, mirroring
	// register.validateRedirectURI so the relaxed path can never accept a shape
	// registration itself forbids.
	if req.User != nil || req.Fragment != "" || strings.Contains(requested, "#") {
		return false
	}

	for _, r := range registered {
		reg, err := url.Parse(r)
		if err != nil || strings.ToLower(reg.Scheme) != "http" || !isLoopbackHost(reg.Hostname()) {
			continue
		}
		// Port ignored; everything else must match exactly.
		if strings.EqualFold(reg.Hostname(), req.Hostname()) &&
			reg.Path == req.Path &&
			reg.RawQuery == req.RawQuery {
			return true
		}
	}
	return false
}

// isLoopbackHost reports whether host is an RFC 8252 loopback redirect host.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// HTTPSRedirectHosts restricts which hosts an https redirect URI may use
// (DCR_ALLOWED_REDIRECT_HOSTS). A nil *HTTPSRedirectHosts is unrestricted (any
// https host, the back-compat default). A non-nil value with no hosts rejects
// every https redirect URI. Loopback http and private-use schemes are never
// affected.
type HTTPSRedirectHosts struct {
	hosts map[string]struct{}
}

// ParseHTTPSRedirectHosts parses the setting value. "none" or an empty value
// (after trimming) yields a policy that rejects all https redirect URIs.
// Otherwise the value is a comma-separated list of bare hostnames (no scheme,
// path, port, wildcard or userinfo); empty entries are ignored and names are
// lowercased. "none" cannot be combined with hosts.
func ParseHTTPSRedirectHosts(raw string) (*HTTPSRedirectHosts, error) {
	p := &HTTPSRedirectHosts{hosts: map[string]struct{}{}}
	var entries []string
	for _, e := range strings.Split(raw, ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			entries = append(entries, e)
		}
	}
	if len(entries) == 1 && entries[0] == "none" {
		return p, nil
	}
	for _, e := range entries {
		if e == "none" || !validHostname(e) {
			return nil, fmt.Errorf("DCR allowed redirect hosts: invalid entry %q: must be a bare hostname (no scheme, path, port or wildcard); use \"none\" alone to reject all https", e)
		}
		p.hosts[e] = struct{}{}
	}
	return p, nil
}

// AllowsRedirectURI reports whether raw is permitted by the policy. Only https
// URIs are restricted: the hostname (port ignored, case-insensitive) must
// exactly equal a configured host. Any other scheme returns true.
func (p *HTTPSRedirectHosts) AllowsRedirectURI(raw string) bool {
	if p == nil {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if strings.ToLower(u.Scheme) != "https" {
		return true
	}
	_, ok := p.hosts[strings.ToLower(u.Hostname())]
	return ok
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 || h[0] == '.' || h[len(h)-1] == '.' || h[0] == '-' || h[len(h)-1] == '-' {
		return false
	}
	for _, c := range h {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}
