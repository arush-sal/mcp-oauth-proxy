package cmd

import (
	"testing"

	"github.com/gptscript-ai/cmd"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/handlerutils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveDCRHosts runs the real flag/env binding for RootCmd and returns the
// DCRAllowedRedirectHosts value Run would put in types.Config.
func resolveDCRHosts(t *testing.T, args ...string) *string {
	t.Helper()
	p := &probeCmd{}
	cc := cmd.Command(p)
	cc.SetArgs(append([]string{"--oauth-client-id=x", "--oauth-client-secret=y", "--oauth-authorize-url=https://idp.example"}, args...))
	require.NoError(t, cc.Execute())
	return p.got
}

// probeCmd reuses RootCmd's flag/env binding but replaces Run so no server
// starts.
type probeCmd struct {
	RootCmd
	got *string
}

func (p *probeCmd) Run(c *cobra.Command, _ []string) error {
	p.got = p.RootCmd.dcrAllowedRedirectHosts(c)
	return nil
}

func TestDCRAllowedRedirectHostsWiring(t *testing.T) {
	const (
		allowed    = "https://claude.ai/cb"
		disallowed = "https://attacker.example/cb"
		loopback   = "http://127.0.0.1:1/cb"
	)
	policyFor := func(t *testing.T, s *string) *handlerutils.HTTPSRedirectHosts {
		t.Helper()
		if s == nil {
			return nil
		}
		p, err := handlerutils.ParseHTTPSRedirectHosts(*s)
		require.NoError(t, err)
		return p
	}

	t.Run("unset is unrestricted", func(t *testing.T) {
		got := resolveDCRHosts(t)
		require.Nil(t, got)
		assert.True(t, policyFor(t, got).AllowsRedirectURI(disallowed))
	})
	t.Run("env set empty rejects all https", func(t *testing.T) {
		t.Setenv("DCR_ALLOWED_REDIRECT_HOSTS", "")
		p := policyFor(t, resolveDCRHosts(t))
		require.NotNil(t, p)
		assert.False(t, p.AllowsRedirectURI(allowed))
		assert.True(t, p.AllowsRedirectURI(loopback))
	})
	t.Run("env list", func(t *testing.T) {
		t.Setenv("DCR_ALLOWED_REDIRECT_HOSTS", "claude.ai")
		p := policyFor(t, resolveDCRHosts(t))
		require.NotNil(t, p)
		assert.True(t, p.AllowsRedirectURI(allowed))
		assert.False(t, p.AllowsRedirectURI(disallowed))
	})
	t.Run("flag empty rejects all https", func(t *testing.T) {
		p := policyFor(t, resolveDCRHosts(t, "--dcr-allowed-redirect-hosts="))
		require.NotNil(t, p)
		assert.False(t, p.AllowsRedirectURI(allowed))
	})
	t.Run("flag list", func(t *testing.T) {
		p := policyFor(t, resolveDCRHosts(t, "--dcr-allowed-redirect-hosts=claude.ai"))
		require.NotNil(t, p)
		assert.True(t, p.AllowsRedirectURI(allowed))
	})
}
