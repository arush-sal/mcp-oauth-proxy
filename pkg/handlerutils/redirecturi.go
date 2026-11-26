package handlerutils

import (
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
