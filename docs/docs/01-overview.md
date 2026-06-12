---
title: Overview
slug: /
---

MCP OAuth Proxy is an open-source OAuth 2.1 proxy server that adds authentication and authorization to MCP (Model Context Protocol) servers.

## What is MCP OAuth Proxy?

MCP OAuth Proxy acts as a bridge between OAuth providers (Google, Microsoft, GitHub) and MCP servers, providing:

- **OAuth 2.1 Compliance** - Full OAuth 2.1 authorization server with PKCE support
- **MCP Integration** - Seamless proxy to MCP servers with user context injection
- **Multi-Provider Support** - Works with any OAuth 2.0 provider via auto-discovery
- **Access Control** - Optional email / domain / group allowlist enforced directly against the identity provider, deny-by-default when configured (see [Authorization](/getting-started#authorization--allowlist))
- **Database Flexibility** - PostgreSQL for production, SQLite for development
- **Observability** - Liveness / readiness probes and optional Prometheus metrics

## Architecture

The proxy sits in front of your MCP server to handle OAuth 2.1 authentication and validate user identity from external providers.

Here's how it works:

1. **OAuth 2.1 Flow** - When a client needs access, the proxy redirects to an external auth provider (Google, Microsoft, GitHub) to verify user identity
2. **Token Issuance** - Once authentication is complete, the proxy issues an access token back to the client
3. **MCP Auth Compliance** - Follows the MCP authentication specification and works with any compatible MCP client
4. **Request Proxying** - Validates the access token and forwards authenticated requests to your MCP server
5. **User Context** - Sends necessary headers to the MCP server about user identity and access to external services based on the OAuth scopes you configured

![Architecture Diagram](/img/architect.png)

The proxy supports PostgreSQL for production deployments and SQLite for development, with automatic schema creation and encrypted storage for sensitive data.

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

:::note
Headers are only set if the corresponding user information is available from the OAuth provider. If a property is not available, the header is removed to avoid stale data.
:::

:::info
**Who reaches the upstream is configurable.** By default any user the OAuth provider authenticates is forwarded. Once you configure an allowlist (`ALLOWED_EMAILS`, `ALLOWED_EMAIL_DOMAINS`, `ALLOWED_GROUPS`, `ALLOWED_GOOGLE_HOSTED_DOMAINS`), access becomes **deny-by-default**: only matching users reach the MCP server, everyone else gets a `403`. See [Authorization & allowlist](/getting-started#authorization--allowlist).
:::

The proxy always strips any inbound `Authorization` header and overwrites the four `X-Forwarded-*` headers above, so a client cannot spoof them. You can additionally:

- **Forward the OIDC ID token** (a verifiable JWT) to the upstream for downstream validation (e.g. Grafana `[auth.jwt]`) with `AUTHORIZATION_HEADER_TOKEN` / `ID_TOKEN_HEADER`.
- **Strip a broader set of inbound identity headers** (`X-Auth-Request-*`, `X-Forwarded-Groups`, `X-Remote-User`, ...) with `STRIP_INBOUND_IDENTITY_HEADERS`.

See [Forwarding identity to the upstream](/getting-started#forwarding-identity-to-the-upstream).

## Next Steps

- [Getting Started](/getting-started) - Quick setup guide
