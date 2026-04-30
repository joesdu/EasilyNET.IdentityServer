# EasilyNET.IdentityServer

> A lightweight OAuth 2.1 / OpenID Connect server for .NET 11, with modern client authentication, interactive authorization, and an accompanying admin console.

[English](./README.md) | [中文](./README.zh-CN.md)

## Overview

`EasilyNET.IdentityServer` is a layered identity server implementation built around OAuth 2.1-era defaults:

- authorization code with mandatory PKCE
- refresh token rotation and replay protection
- client credentials and device authorization grant
- OpenID Connect discovery, JWKS, and `userinfo`
- dynamic client registration
- modern client authentication with `private_key_jwt`, mutual TLS, and DPoP

The repository also includes:

- a REST admin API backed by EF Core
- a React + Umi + Ant Design admin UI
- integration and unit tests for protocol behavior, security rules, and infrastructure services
- a Chinese translation of the OAuth 2.1 draft under `docs/`

## Highlights

- **OAuth 2.1-oriented defaults**: PKCE required, no implicit flow, refresh token rotation enabled by design.
- **OpenID Connect endpoints**: discovery document, JWKS, end-session metadata, and `userinfo`.
- **Interactive authorization flow**: login, `select_account`, and consent steps exposed through dedicated interaction endpoints.
- **Advanced client authentication**: supports `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`, and public clients where appropriate.
- **DPoP support**: issues and validates DPoP-bound access tokens.
- **Dynamic client registration**: `/connect/register` implements RFC 7591-style registration.
- **Resource-side token validation**: `/connect/verify` validates bearer or DPoP-bound access tokens and returns RFC 6750-style errors.
- **Operational safeguards**: rate limiting, audit logging, forwarded client certificate handling, and security response headers.
- **Pluggable persistence**: abstractions plus EF Core and MongoDB storage implementations.
- **Admin tooling included**: CRUD APIs and a web console for clients and resources.

## Solution layout

```
┌─────────────────────────────────────────────────────────────┐
│                      Solution Layers                        │
├─────────────────────────────────────────────────────────────┤
│  Apps          │ Host │ Admin.Api │ Admin UI                │
├────────────────┼────────────────────────────────────────────┤
│  Core          │ Token, auth, interaction, security         │
├────────────────┼────────────────────────────────────────────┤
│  Abstractions  │ Models, interfaces, options               │
├────────────────┼────────────────────────────────────────────┤
│  Persistence   │ EF Core providers │ MongoDB               │
└─────────────────────────────────────────────────────────────┘
```

### Projects

| Project                                                | Purpose                                                                                                                      |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `src/EasilyNET.IdentityServer.Abstractions`            | Domain models, store interfaces, service contracts, configuration options                                                    |
| `src/EasilyNET.IdentityServer.Core`                    | Token issuance/validation, client auth, authorization interaction, DPoP, mTLS, dynamic registration, auditing, rate limiting |
| `src/EasilyNET.IdentityServer.DataAccess.Abstractions` | Persistence contracts                                                                                                        |
| `src/EasilyNET.IdentityServer.DataAccess.EFCore`       | EF Core entities, DbContext, and store implementations                                                                       |
| `src/EasilyNET.IdentityServer.DataAccess.EFCore.*`     | Database-specific EF Core provider packages                                                                                  |
| `src/EasilyNET.IdentityServer.DataAccess.MongoDB`      | MongoDB-based store implementations                                                                                          |
| `src/EasilyNET.IdentityServer.Host`                    | OAuth/OIDC host app with in-memory development stores                                                                        |
| `src/EasilyNET.IdentityServer.Admin.Api`               | Admin API for clients and resource management                                                                                |
| `src/EasilyNET.IdentityServer.Admin`                   | React/Umi admin console and authorization interaction UI                                                                     |
| `tests/EasilyNET.IdentityServer.IntegrationTests`      | End-to-end protocol tests                                                                                                    |
| `tests/EasilyNET.IdentityServer.Core.Tests`            | Unit tests for core services                                                                                                 |

## Implemented protocol surface

### Host endpoints

The host application exposes the following public endpoints in the current implementation:

| Endpoint                                              | Purpose                                                      | Other                   |
| ----------------------------------------------------- | ------------------------------------------------------------ | ----------------------- |
| `GET /.well-known/openid-configuration`               | Discovery metadata                                           |
| `GET /.well-known/jwks`                               | JSON Web Key Set                                             |
| `GET /connect/authorize`                              | Authorization endpoint                                       |
| `GET /connect/authorize/context/{requestId}`          | Retrieve authorization interaction context                   |
| `GET /connect/authorize/interaction/page/{requestId}` | Stable entry point that redirects to the UI interaction page |
| `POST /connect/authorize/interaction`                 | Continue login / account selection / consent interactions    |
| `POST /connect/token`                                 | Token endpoint                                               |
| `GET                                                  | POST /connect/userinfo`                                      | OpenID Connect UserInfo |
| `POST /connect/introspect`                            | Token introspection                                          |
| `POST /connect/revocation`                            | Token revocation                                             |
| `POST /connect/register`                              | Dynamic client registration                                  |
| `POST /connect/device_authorization`                  | Device authorization                                         |
| `POST /connect/device_verify`                         | Simplified device user-code verification                     |
| `POST /connect/verify`                                | Resource-server-facing access token validation               |
| `GET /health`                                         | Health check                                                 |

### Supported grants and interaction modes

- `authorization_code` with PKCE
- `refresh_token`
- `client_credentials`
- `urn:ietf:params:oauth:grant-type:device_code`
- interactive login handoff when the end-user is missing
- `prompt=login`, `prompt=consent`, and `prompt=select_account`
- consent remembering and client-specific prompt restrictions
- identity-provider restrictions for selected clients

### Supported client authentication methods

- `client_secret_basic`
- `client_secret_post`
- `private_key_jwt`
- `tls_client_auth`
- `self_signed_tls_client_auth`
- `none` for public clients

## Quick start

### Prerequisites

- .NET 11 SDK / preview toolchain
- bun 1.3.x for the admin frontend

### Build from the repository root

```bash
dotnet build EasilyNET.IdentityServer.slnx -v minimal
```

### Run the integration tests

```bash
dotnet test tests/EasilyNET.IdentityServer.IntegrationTests/EasilyNET.IdentityServer.IntegrationTests.csproj -v minimal
```

### Run the host app

```bash
cd src/EasilyNET.IdentityServer.Host
dotnet run
```

In the development launch profile, the host listens on:

- `https://localhost:7020`
- `http://localhost:5093`

The configured issuer is `https://localhost:7020`.

### Run the admin API

```bash
cd src/EasilyNET.IdentityServer.Admin.Api
dotnet run
```

The current development launch profile exposes the admin API on:

- `http://localhost:5104`

On startup, the admin API applies EF Core migrations automatically and uses SQLite by default when no connection string is supplied.

### Run the admin frontend

```bash
cd src/EasilyNET.IdentityServer.Admin
bun install
bun run start
```

Useful frontend scripts:

```bash
bun run build
bun run preview
```

The frontend is built with `@umijs/max` and Ant Design. It includes both the admin console and the `/authorize/interaction` page used by the interactive authorization flow.

## Admin API capabilities

The admin API currently manages the following resource types:

### Clients

- list, create, update, delete clients
- configure grant types, scopes, redirect URIs, CORS origins
- configure prompt restrictions and identity provider restrictions
- set token lifetimes, consent behavior, and PKCE/client-secret requirements

### API resources

- list, create, update, delete API resources
- assign scopes and user claims

### API scopes

- list, create, delete API scopes
- define required/emphasized flags and user claims

### Identity resources

- list, create, delete identity resources
- configure required/emphasized flags, discovery visibility, and user claims

## Development defaults

### Host defaults

The sample host app is wired for local development with:

- in-memory clients, resources, persisted grants, device codes, signing keys, and audit log storage
- issuer `https://localhost:7020`
- access token lifetime `3600` seconds
- refresh token lifetime `86400` seconds
- authorization code lifetime `300` seconds
- PKCE required
- consent disabled globally in the sample host, while specific sample clients can still require consent
- DPoP, dynamic client registration, mutual TLS, and `private_key_jwt` enabled by default in `IdentityServerOptions`

### Sample in-memory clients

The development host seeds several useful clients:

| Client ID           | Type         | Purpose                                         |
| ------------------- | ------------ | ----------------------------------------------- |
| `console`           | confidential | client credentials flow                         |
| `mvc`               | confidential | authorization code + refresh token              |
| `spa`               | public       | PKCE-based SPA sign-in                          |
| `interactive`       | public       | consent-focused authorization interaction demos |
| `restricted-github` | public       | client with identity provider restrictions      |
| `prompt-restricted` | public       | client with restricted prompt values            |
| `device`            | public       | device authorization grant                      |

## Security and protocol behavior

The current implementation includes several security-focused behaviors that are worth calling out explicitly:

- refresh token rotation and refresh-token-family replay revocation
- authorization code replay detection with previously issued tokens revoked on replay
- rate limiting with response headers and `429` handling
- clickjacking and hardening headers on authorization responses
- RFC 6750-style `WWW-Authenticate` responses for protected resource token failures
- mTLS client certificate forwarding support
- DPoP proof validation at both token and resource endpoints
- audit logging for protocol activity such as `userinfo` access

## Test coverage

Automated tests in this repository cover:

- discovery metadata and JWKS
- client credentials, authorization code, refresh token, device flow
- interaction-required login, account selection, and consent continuation flows
- introspection, revocation, and resource token verification
- dynamic client registration
- `private_key_jwt`, mutual TLS, and DPoP
- rate limiting behavior
- core services such as secret hashing, client authentication, audit logging, and rate limiting

## Related documentation

- `docs/` contains a Chinese translation of `draft-ietf-oauth-v2-1-15`
- `OAUTH_IMPLEMENTATION_STATUS.md` and `IMPLEMENTATION_SUMMARY.md` summarize implementation progress in this repository

## License

MIT License. See `LICENSE` for details.
