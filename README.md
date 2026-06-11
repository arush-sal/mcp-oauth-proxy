# MCP OAuth Proxy

MCP OAuth Proxy is an open-source OAuth 2.1 proxy server that adds authentication and authorization to MCP (Model Context Protocol) servers.

## What is MCP OAuth Proxy?

MCP OAuth Proxy acts as a bridge between OAuth providers (Google, Microsoft, GitHub) and MCP servers, providing:

- **OAuth 2.1 Compliance** - Full OAuth 2.1 authorization server with PKCE support
- **MCP Integration** - Seamless proxy to MCP servers with user context injection
- **Multi-Provider Support** - Works with any OAuth 2.0 provider via auto-discovery
- **Database Flexibility** - PostgreSQL for production, SQLite for development

## Architecture

The proxy sits in front of your MCP server to handle OAuth 2.1 authentication and validate user identity from external providers.

Here's how it works:

1. **OAuth 2.1 Flow** - When a client needs access, the proxy redirects to an external auth provider (Google, Microsoft, GitHub) to verify user identity
2. **Token Issuance** - Once authentication is complete, the proxy issues an access token back to the client
3. **MCP Auth Compliance** - Follows the MCP authentication specification and works with any compatible MCP client
4. **Request Proxying** - Validates the access token and forwards authenticated requests to your MCP server
5. **User Context** - Sends necessary headers to the MCP server about user identity and access to external services based on the OAuth scopes you configured

## Headers Sent to MCP Server

When proxying requests to your MCP server, the OAuth proxy automatically injects the following headers with user information:

| Header                     | Description                               | Example                |
| -------------------------- | ----------------------------------------- | ---------------------- |
| `X-Forwarded-User`         | User ID from the OAuth provider           | `12345678901234567890` |
| `X-Forwarded-Email`        | User's email address                      | `user@example.com`     |
| `X-Forwarded-Name`         | User's display name                       | `John Doe`             |
| `X-Forwarded-Access-Token` | OAuth access token for external API calls | `ya29.a0ARrdaM...`     |

These headers allow your MCP server to:

- **Identify the user** making the request
- **Personalize responses** based on user information
- **Make authenticated API calls** to external services using the access token
- **Implement user-specific logic** and access controls

## Quick Start

### Prerequisites

- Docker installed on your system
- An OAuth provider account (Google, Microsoft, GitHub, etc.)
- A running MCP server to proxy to

### 1. Setup OAuth Credentials

OAuth credentials (Client ID and Client Secret) are used by the proxy to authenticate with external providers on behalf of your users.

#### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/) and create a new project
2. Enable Google+ API in "APIs & Services" > "Library"
3. Configure OAuth consent screen and add authorized users
4. Create OAuth Client:
   - Go to "Credentials" > "Create Credentials" > "OAuth 2.0 Client IDs"
   - Choose "Web application" type
   - Add `http://localhost:8080/callback` as redirect URI
   - Copy your **Client ID** and **Client Secret**

#### Microsoft OAuth

1. Go to [Azure Portal](https://portal.azure.com/) > "Azure Active Directory"
2. Register a new application with redirect URI `http://localhost:8080/callback`
3. Configure API permissions (Microsoft Graph: `User.Read`, `Mail.Read`)
4. Create client secret and copy **Application (client) ID** and **Client Secret**

#### GitHub OAuth

1. Go to GitHub Settings > Developer settings > [OAuth Apps](https://github.com/settings/applications/new)
2. Create OAuth App with callback URL `http://localhost:8080/callback`
3. Copy **Client ID** and generate **Client Secret**

### 2. Setup Your MCP Server

The OAuth proxy requires a streamable HTTP MCP server. Example using Obot's Gmail MCP server:

```bash
git clone https://github.com/obot-platform/tools
cd google/gmail
uv run python -m obot_gmail_mcp.server
```

This starts the server at `http://localhost:9000/mcp/gmail`.

### 3. Run OAuth Proxy

#### Option A: Docker

```bash
docker run -d --name mcp-oauth-proxy -p 8080:8080 \
  -e OAUTH_CLIENT_ID="your-client-id" \
  -e OAUTH_CLIENT_SECRET="your-client-secret" \
  -e OAUTH_AUTHORIZE_URL="https://accounts.google.com" \
  -e SCOPES_SUPPORTED="openid,email,profile,https://www.googleapis.com/auth/gmail.readonly" \
  -e MCP_SERVER_URL="http://localhost:9000/mcp/gmail" \
  -e ENCRYPTION_KEY="your-encryption-key" \
  ghcr.io/obot-platform/mcp-oauth-proxy:latest
```

#### Option B: CLI Binary

1. Download from [GitHub Releases](https://github.com/obot-platform/mcp-oauth-proxy/releases)
2. Run with environment variables:

```bash
export OAUTH_CLIENT_ID="your-client-id"
export OAUTH_CLIENT_SECRET="your-client-secret"
export OAUTH_AUTHORIZE_URL="https://accounts.google.com"
export SCOPES_SUPPORTED="openid,email,profile,https://www.googleapis.com/auth/gmail.readonly"
export MCP_SERVER_URL="http://localhost:9000/mcp/gmail"
export ENCRYPTION_KEY="your-encryption-key"

./mcp-oauth-proxy
```

## Environment Variables

| Variable              | Required | Description                                               |
| --------------------- | -------- | --------------------------------------------------------- |
| `OAUTH_CLIENT_ID`     | ✅       | OAuth client ID from provider                             |
| `OAUTH_CLIENT_SECRET` | ✅       | OAuth client secret                                       |
| `OAUTH_AUTHORIZE_URL` | ✅       | Provider's base URL (e.g., `https://accounts.google.com`) |
| `SCOPES_SUPPORTED`    | ✅       | Comma-separated OAuth scopes                              |
| `MCP_SERVER_URL`      | ✅       | Your MCP server endpoint                                  |
| `DATABASE_DSN`        | ❌       | Database connection string (defaults to SQLite)           |
| `ENCRYPTION_KEY`      | ✅       | Base64-encoded 32-byte AES key                            |
| `OAUTH_JWKS_URL`      | ❌       | Provider JWKS endpoint (enables id_token verification)    |
| `OAUTH_ISSUER_URL`    | ❌       | Expected id_token issuer (`iss`); see Authorization below |
| `ALLOWED_EMAILS`            | ❌ | Comma-separated allowed email addresses                          |
| `ALLOWED_EMAILS_FILE`       | ❌ | Path to a file of allowed emails (one per line)                  |
| `ALLOWED_EMAIL_DOMAINS`     | ❌ | Comma-separated allowed email domains; `*` allows ANY user       |
| `ALLOWED_GROUPS`            | ❌ | Comma-separated allowed groups                                   |
| `GROUPS_CLAIM`              | ❌ | id_token claim carrying groups (default `groups`)                |
| `ALLOWED_GOOGLE_HOSTED_DOMAINS` | ❌ | Comma-separated allowed Google hosted domains (`hd` claim)  |
| `AUTHORIZATION_HEADER_TOKEN` | ❌ | Token to forward on the upstream `Authorization` header: `none` (default), `access_token`, or `id_token`. See "Forwarding the ID token to the upstream" |
| `ID_TOKEN_HEADER`           | ❌ | Custom header to carry the raw verified id_token (no `Bearer ` prefix). When empty and forwarding the id_token, uses `Authorization: Bearer <id_token>` |
| `COOKIE_EXPIRE`             | ❌ | Access-token / access-cookie lifetime as a Go duration string (e.g. `30m`, `1h`, `2h`). Default `1h`. Must be positive. See "Session & cookie lifetime" |
| `COOKIE_REFRESH`            | ❌ | Refresh-token / refresh-cookie lifetime **and** grant expiry, as a Go duration string (e.g. `720h`). Default `720h` (30 days). Must be positive |
| `COOKIE_SECURE`             | ❌ | Cookie `Secure` attribute policy: `auto` (default; Secure when the request is HTTPS), `true` (always), or `false` (never) |
| `COOKIE_SAMESITE`           | ❌ | Cookie `SameSite` attribute: `lax` (default), `strict`, or `none`. `none` requires `COOKIE_SECURE=true` |

You should generate a random 32-byte AES key for the `ENCRYPTION_KEY` environment variable using the following command:

```bash
openssl rand -base64 32
```

### Session & cookie lifetime

The session/cookie lifetimes and cookie security attributes are configurable.
**The defaults reproduce the previous behavior exactly**, so existing deployments
need no changes.

- `COOKIE_EXPIRE` (default `1h`) sets the access-token lifetime, the access
  cookie `Max-Age`, and the `expires_in` value in token responses.
- `COOKIE_REFRESH` (default `720h`, i.e. 30 days) sets the refresh-token
  lifetime, the refresh cookie `Max-Age`, and the authorization grant expiry
  (which mirrors the refresh token, as before).
- Both accept a Go duration string parsed with
  [`time.ParseDuration`](https://pkg.go.dev/time#ParseDuration) (e.g. `30m`,
  `90m`, `2h`, `720h`). Values must be strictly positive; a non-positive or
  unparseable value is rejected at startup.
- `COOKIE_SECURE` controls the cookie `Secure` attribute: `auto` (default) sets
  `Secure` only when the request is detected as HTTPS (preserving the prior
  behavior), `true` always sets it, and `false` never sets it.
- `COOKIE_SAMESITE` controls the cookie `SameSite` attribute: `lax` (default),
  `strict`, or `none`.

> [!NOTE]
> `COOKIE_SAMESITE=none` requires `COOKIE_SECURE=true`. Browsers reject
> `SameSite=None` cookies that are not also `Secure`, so this combination is
> rejected at startup with a clear error. (`auto` is not sufficient because it
> cannot guarantee the cookie is always marked `Secure`.)

## Authorization / Allowlist

> [!WARNING]
> **BREAKING CHANGE — DENY-ALL BY DEFAULT.** With **none** of the `ALLOWED_*`
> variables set, the proxy now **denies every authenticated user** (fail-closed,
> for parity with oauth2-proxy). This is a deliberate change from the previous
> "any authenticated user is allowed" behavior. To restore the old open behavior
> explicitly, set `ALLOWED_EMAIL_DOMAINS=*`.

The proxy enforces **who** may use it directly against the verified IdP identity,
in addition to verifying that the user is authenticated. Authorization is decided
**claims-first** off the verified `id_token`, falling back to the provider
userinfo endpoint only for an attribute a configured rule needs but the
`id_token` did not supply. If a required attribute is still missing, the request
is **denied** (fail-closed).

### Rules

If any allow input is set, a request is allowed if it matches **at least one**
rule (rules OR together); otherwise it is denied with a clear `403`
(`access_denied`).

- **`ALLOWED_EMAILS`** / **`ALLOWED_EMAILS_FILE`** — explicit email addresses.
  Matching is case-insensitive and trimmed. The file lists one email per line;
  blank lines and lines starting with `#` are ignored. The file is **merged**
  with `ALLOWED_EMAILS` and loaded **once at startup** (reload requires a
  restart).
- **`ALLOWED_EMAIL_DOMAINS`** — the domain after `@`, case-insensitive. The
  special value `*` allows **any** authenticated user (the escape hatch that
  restores the legacy open behavior; mirrors oauth2-proxy `--email-domain=*`).
- **`ALLOWED_GROUPS`** — allowed if the user's groups intersect this list. The
  groups claim name is configurable via **`GROUPS_CLAIM`** (default `groups`).
- **`ALLOWED_GOOGLE_HOSTED_DOMAINS`** — checked against the OIDC `hd` claim.

> [!NOTE]
> **Email verification required.** An email or email-domain rule is satisfied
> only when the IdP asserts `email_verified == true`. An unverified email will
> NOT match an email/domain rule.

### Re-checked on every refresh

The allowlist is re-evaluated on **every token refresh**. If a previously
allowed user no longer matches (e.g. removed from `ALLOWED_EMAILS`), their
session is revoked on the next refresh and they must re-authenticate (the agent
receives a `401`; browser sessions are sent back through login). When a refresh
returns a fresh `id_token` it is re-verified and the stored claims are updated
before the re-check; otherwise the stored claims (or userinfo) are used.

### `OAUTH_ISSUER_URL`

When verifying the IdP `id_token`, the expected issuer (`iss`) defaults to the
origin (`scheme://host`) of `OAUTH_AUTHORIZE_URL`. For providers with a
path-based issuer (e.g. Keycloak `https://host/realms/your-realm`), set
`OAUTH_ISSUER_URL` to the exact issuer string; it overrides the derived value.

### Recipe: drop Keycloak, point at Google directly

```bash
export OAUTH_CLIENT_ID="...apps.googleusercontent.com"
export OAUTH_CLIENT_SECRET="..."
export OAUTH_AUTHORIZE_URL="https://accounts.google.com"
export OAUTH_JWKS_URL="https://www.googleapis.com/oauth2/v3/certs"
export SCOPES_SUPPORTED="openid,profile,email"
# Authorize exactly who may use the proxy:
export ALLOWED_EMAILS="alice@example.com,bob@example.com"
# or by domain / Google hosted domain:
# export ALLOWED_EMAIL_DOMAINS="example.com"
# export ALLOWED_GOOGLE_HOSTED_DOMAINS="example.com"
```

**Different Auth Provider URLs:**

- Google: `https://accounts.google.com`
- Microsoft: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize`
- GitHub: `https://github.com/login/oauth/authorize`

## Forwarding the ID token to the upstream

By default the proxy forwards nothing on the upstream `Authorization` header:
the inbound `Authorization` is stripped and the OAuth access token is exposed
only via `X-Forwarded-Access-Token`. Some upstreams want to validate the
**verified OIDC id_token** themselves (for example Grafana's `[auth.jwt]`,
which validates a JWT against the IdP's JWKS). Two settings enable this:

- **`AUTHORIZATION_HEADER_TOKEN`** — `none` (default), `access_token`, or
  `id_token`.
  - `none`: current behavior. No `Authorization` is set on the upstream
    request.
  - `access_token`: sets `Authorization: Bearer <access_token>`.
    `X-Forwarded-Access-Token` is still sent as before.
  - `id_token`: forwards the verified id_token. With no custom header it is
    sent as `Authorization: Bearer <id_token>`.
- **`ID_TOKEN_HEADER`** — optional custom header that carries the **raw**
  id_token (a bare JWT, **no `Bearer ` prefix**), e.g.
  `ID_TOKEN_HEADER=X-Id-Token`. The `Authorization` header always uses the
  `Bearer ` prefix; only custom headers carry the bare JWT.

Example (Grafana validating the id_token via `[auth.jwt]`):

```bash
export OAUTH_JWKS_URL="https://accounts.google.com/.well-known/openid-configuration/jwks"
export AUTHORIZATION_HEADER_TOKEN="id_token"
# or send it on a dedicated header instead of Authorization:
# export ID_TOKEN_HEADER="X-Id-Token"
```

**Startup validation (no silent "one wins").** The proxy refuses to start when
two directives target the same header:

- `AUTHORIZATION_HEADER_TOKEN=id_token` together with a non-empty
  `ID_TOKEN_HEADER` (two directives for the id_token destination — use one).
- `ID_TOKEN_HEADER` resolving to `Authorization` while
  `AUTHORIZATION_HEADER_TOKEN=access_token` (both land on `Authorization`).
- `ID_TOKEN_HEADER` resolving to `X-Forwarded-Access-Token` (collides with the
  proxy's access-token header).
- Any `AUTHORIZATION_HEADER_TOKEN` value outside `none|access_token|id_token`.

**Staleness / refresh caveat.** id_tokens are short-lived. Before forwarding,
the proxy checks the stored id_token's `exp` and **never forwards a stale (or
absent) token** — the header is simply omitted. On an IdP token refresh the
proxy re-verifies and updates the stored id_token; however, **if the IdP does
not issue a fresh id_token on refresh, forwarding stops** (the header is
omitted) rather than sending an expired token. Request a refresh-capable
id_token (e.g. include the `openid` scope and, where required by the provider,
`access_type=offline`) if you rely on continuous id_token forwarding.

## VSCode Setup

Create a `.vscode/mcp.json` file in your workspace:

```json
{
  "servers": {
    "oauth-gmail": {
      "type": "http",
      "url": "http://localhost:8080/mcp/gmail"
    }
  }
}
```

**Authentication Flow:**

- VSCode opens browser for OAuth authentication
- Sign in with your account and grant permissions
- VSCode receives access token and communicates with the Gmail MCP server
- Use Copilot panel to interact with your emails

## License

This project is licensed under the Apache License 2.0.
