package cmd

import (
	"os"
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
// starts. It reads the value through buildConfig, the same path Run uses.
type probeCmd struct {
	RootCmd
	got *string
}

func (p *probeCmd) Run(c *cobra.Command, _ []string) error {
	p.got = p.RootCmd.buildConfig(c).DCRAllowedRedirectHosts
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
		// Make sure ambient env cannot leak in; restore it afterwards.
		if old, ok := os.LookupEnv("DCR_ALLOWED_REDIRECT_HOSTS"); ok {
			t.Cleanup(func() { _ = os.Setenv("DCR_ALLOWED_REDIRECT_HOSTS", old) })
		}
		require.NoError(t, os.Unsetenv("DCR_ALLOWED_REDIRECT_HOSTS"))
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
	t.Run("flag takes precedence over env", func(t *testing.T) {
		t.Setenv("DCR_ALLOWED_REDIRECT_HOSTS", "attacker.example")
		p := policyFor(t, resolveDCRHosts(t, "--dcr-allowed-redirect-hosts=claude.ai"))
		require.NotNil(t, p)
		assert.True(t, p.AllowsRedirectURI(allowed))
		assert.False(t, p.AllowsRedirectURI(disallowed))
	})
	t.Run("flag list", func(t *testing.T) {
		p := policyFor(t, resolveDCRHosts(t, "--dcr-allowed-redirect-hosts=claude.ai"))
		require.NotNil(t, p)
		assert.True(t, p.AllowsRedirectURI(allowed))
	})
}
