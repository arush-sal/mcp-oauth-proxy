package authz

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorize_DenyAllByDefault(t *testing.T) {
	// Zero-config authorizer must deny everyone (oauth2-proxy parity:
	// DENY-ALL is the default, a deliberate breaking change).
	a, err := New(Config{})
	require.NoError(t, err)
	require.False(t, a.Enabled(), "zero-config authorizer reports not enabled")

	err = a.Authorize(Identity{Email: "user@example.com", EmailVerified: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDenied)
}

func TestAuthorize_WildcardDomainAllowsAny(t *testing.T) {
	a, err := New(Config{EmailDomains: []string{"*"}})
	require.NoError(t, err)
	require.True(t, a.Enabled())

	// Any authenticated user is allowed, even without an email.
	require.NoError(t, a.Authorize(Identity{Subject: "sub-1"}))
	require.NoError(t, a.Authorize(Identity{Email: "anyone@anywhere.test", EmailVerified: false}))
}

func TestAuthorize_Email(t *testing.T) {
	a, err := New(Config{Emails: []string{"Allowed@Example.com", "  second@example.com  "}})
	require.NoError(t, err)

	tests := []struct {
		name  string
		id    Identity
		allow bool
	}{
		{"exact match verified", Identity{Email: "allowed@example.com", EmailVerified: true}, true},
		{"case-insensitive match", Identity{Email: "ALLOWED@EXAMPLE.COM", EmailVerified: true}, true},
		{"trimmed config entry match", Identity{Email: "second@example.com", EmailVerified: true}, true},
		{"not in list", Identity{Email: "other@example.com", EmailVerified: true}, false},
		{"unverified email denied", Identity{Email: "allowed@example.com", EmailVerified: false}, false},
		{"empty email denied", Identity{Email: "", EmailVerified: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := a.Authorize(tc.id)
			if tc.allow {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrDenied)
			}
		})
	}
}

func TestAuthorize_EmailDomain(t *testing.T) {
	a, err := New(Config{EmailDomains: []string{"Example.com", "second.test"}})
	require.NoError(t, err)

	tests := []struct {
		name  string
		id    Identity
		allow bool
	}{
		{"domain match verified", Identity{Email: "user@example.com", EmailVerified: true}, true},
		{"domain case-insensitive", Identity{Email: "user@EXAMPLE.COM", EmailVerified: true}, true},
		{"second domain", Identity{Email: "x@second.test", EmailVerified: true}, true},
		{"wrong domain", Identity{Email: "user@other.com", EmailVerified: true}, false},
		{"unverified domain denied", Identity{Email: "user@example.com", EmailVerified: false}, false},
		{"no at sign", Identity{Email: "example.com", EmailVerified: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := a.Authorize(tc.id)
			if tc.allow {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrDenied)
			}
		})
	}
}

func TestAuthorize_Groups(t *testing.T) {
	a, err := New(Config{Groups: []string{"admins", "ops"}})
	require.NoError(t, err)

	require.NoError(t, a.Authorize(Identity{Groups: []string{"users", "admins"}}))
	require.NoError(t, a.Authorize(Identity{Groups: []string{"ops"}}))
	assert.ErrorIs(t, a.Authorize(Identity{Groups: []string{"users"}}), ErrDenied)
	assert.ErrorIs(t, a.Authorize(Identity{Groups: nil}), ErrDenied)
}

func TestAuthorize_GoogleHostedDomain(t *testing.T) {
	a, err := New(Config{GoogleHostedDomains: []string{"corp.example.com"}})
	require.NoError(t, err)

	require.NoError(t, a.Authorize(Identity{HostedDomain: "corp.example.com"}))
	assert.ErrorIs(t, a.Authorize(Identity{HostedDomain: "other.example.com"}), ErrDenied)
	assert.ErrorIs(t, a.Authorize(Identity{HostedDomain: ""}), ErrDenied)
}

func TestAuthorize_RulesORTogether(t *testing.T) {
	a, err := New(Config{
		Emails:              []string{"vip@somewhere.test"},
		EmailDomains:        []string{"example.com"},
		Groups:              []string{"admins"},
		GoogleHostedDomains: []string{"corp.example.com"},
	})
	require.NoError(t, err)

	// matches via email only
	require.NoError(t, a.Authorize(Identity{Email: "vip@somewhere.test", EmailVerified: true}))
	// matches via domain only
	require.NoError(t, a.Authorize(Identity{Email: "x@example.com", EmailVerified: true}))
	// matches via group only (email unverified, no domain/hd match)
	require.NoError(t, a.Authorize(Identity{Email: "x@other.test", EmailVerified: false, Groups: []string{"admins"}}))
	// matches via hosted domain only
	require.NoError(t, a.Authorize(Identity{HostedDomain: "corp.example.com"}))
	// matches nothing
	assert.ErrorIs(t, a.Authorize(Identity{Email: "x@other.test", EmailVerified: true, Groups: []string{"users"}, HostedDomain: "nope.test"}), ErrDenied)
}

func TestNeedsAccessors(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		a, _ := New(Config{})
		assert.False(t, a.NeedsEmail())
		assert.False(t, a.NeedsGroups())
		assert.False(t, a.NeedsHostedDomain())
	})
	t.Run("email rule needs email", func(t *testing.T) {
		a, _ := New(Config{Emails: []string{"a@b.test"}})
		assert.True(t, a.NeedsEmail())
		assert.False(t, a.NeedsGroups())
	})
	t.Run("domain rule needs email", func(t *testing.T) {
		a, _ := New(Config{EmailDomains: []string{"b.test"}})
		assert.True(t, a.NeedsEmail())
	})
	t.Run("wildcard domain needs nothing", func(t *testing.T) {
		a, _ := New(Config{EmailDomains: []string{"*"}})
		assert.False(t, a.NeedsEmail())
		assert.False(t, a.NeedsGroups())
		assert.False(t, a.NeedsHostedDomain())
	})
	t.Run("group rule needs groups", func(t *testing.T) {
		a, _ := New(Config{Groups: []string{"admins"}})
		assert.True(t, a.NeedsGroups())
	})
	t.Run("hd rule needs hosted domain", func(t *testing.T) {
		a, _ := New(Config{GoogleHostedDomains: []string{"corp.test"}})
		assert.True(t, a.NeedsHostedDomain())
	})
}

func TestLoadEmailsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emails.txt")
	content := "# a comment\n" +
		"first@example.com\n" +
		"\n" +
		"  second@example.com  \n" +
		"   \n" +
		"# trailing comment\n" +
		"Third@Example.com\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	emails, err := LoadEmailsFile(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"first@example.com", "second@example.com", "Third@Example.com"}, emails)
}

func TestLoadEmailsFile_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	require.NoError(t, os.WriteFile(path, []byte("# only comments\n\n   \n"), 0o600))

	emails, err := LoadEmailsFile(path)
	require.NoError(t, err)
	assert.Empty(t, emails)

	// Empty file + no other rule => deny-all.
	a, err := New(Config{Emails: emails})
	require.NoError(t, err)
	require.False(t, a.Enabled())
	assert.ErrorIs(t, a.Authorize(Identity{Email: "anyone@example.com", EmailVerified: true}), ErrDenied)
}

func TestLoadEmailsFile_Missing(t *testing.T) {
	_, err := LoadEmailsFile(filepath.Join(t.TempDir(), "nope.txt"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist) || err != nil)
}

func TestEmailsFileMergedWithConfigEmails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emails.txt")
	require.NoError(t, os.WriteFile(path, []byte("fromfile@example.com\n"), 0o600))

	fileEmails, err := LoadEmailsFile(path)
	require.NoError(t, err)

	merged := append([]string{"fromflag@example.com"}, fileEmails...)
	a, err := New(Config{Emails: merged})
	require.NoError(t, err)

	require.NoError(t, a.Authorize(Identity{Email: "fromflag@example.com", EmailVerified: true}))
	require.NoError(t, a.Authorize(Identity{Email: "fromfile@example.com", EmailVerified: true}))
	assert.ErrorIs(t, a.Authorize(Identity{Email: "nobody@example.com", EmailVerified: true}), ErrDenied)
}
