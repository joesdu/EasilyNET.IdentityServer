# EasilyNET.IdentityServer

> A lightweight, OAuth 2.1 compliant Identity Server built with .NET 11

[English](./README.md) | [中文](./README.zh-CN.md)

## Features

- **OAuth 2.1 Compliant** - Full implementation of OAuth 2.1 specification
- **Multiple Grant Types** - Client Credentials, Authorization Code (PKCE), Refresh Token, Device Flow
- **Multiple Database Support** - SQLite, SQL Server, PostgreSQL, MySQL (modular packages)
- **JWT Tokens** - Native JWT access tokens with HMAC-SHA256 signing
- **OpenID Connect Ready** - Discovery document, JWKS endpoint
- **Admin API** - RESTful API for managing clients, API resources, scopes
- **Management Frontend** - React-based admin UI with Umi + Ant Design
- **Integration Tests** - 17 comprehensive test cases covering all endpoints

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Solution Layers                        │
├─────────────────────────────────────────────────────────────┤
│  Executable    │  Host (OAuth Server) │  Admin.Api           │
├────────────────┼────────────────────────────────────────────┤
│  Business      │  Core (Token, Auth, Client Auth)            │
├────────────────┼────────────────────────────────────────────┤
│  Contracts     │  Abstractions                               │
├────────────────┼────────────────────────────────────────────┤
│  Persistence   │  DataAccess.EFCore (modular)                │
│                │  DataAccess.MongoDB                         │
└─────────────────────────────────────────────────────────────┘
```

### Project Structure

| Project                   | Purpose                                                           |
| ------------------------- | ----------------------------------------------------------------- |
| `Abstractions`            | Models, service interfaces, store interfaces, configuration       |
| `Core`                    | Token issuance, client authentication, authorization services     |
| `DataAccess.Abstractions` | Database context contracts                                        |
| `DataAccess.EFCore`       | EF Core entities, DbContext, stores (core only)                   |
| `DataAccess.EFCore.*`     | Database-specific packages (SqlServer, Sqlite, PostgreSQL, MySQL) |
| `DataAccess.MongoDB`      | MongoDB store implementations                                     |
| `Host`                    | OAuth 2.1 endpoints, in-memory stores for development             |
| `Admin.Api`               | CRUD API for managing IdentityServer resources                    |
| `Admin`                   | React/Umi frontend for admin interface                            |
| `IntegrationTests`        | End-to-end test suite                                             |

## Quick Start

### Prerequisites

- .NET 11 SDK
- bun 1.3.12 (for frontend)
- bun (for frontend package management)

### Backend Setup

```bash
# Clone the repository
git clone https://github.com/your-org/EasilyNET.IdentityServer.git
cd EasilyNET.IdentityServer

# Build the solution
dotnet build src/EasilyNET.IdentityServer.slnx

# Run integration tests
dotnet test tests/EasilyNET.IdentityServer.IntegrationTests
```

### Running the OAuth Server (Host)

```bash
cd src/EasilyNET.IdentityServer.Host
dotnet run
```

The server runs at `https://localhost:5001` with the following endpoints:

| Endpoint                            | Description                     |
| ----------------------------------- | ------------------------------- |
| `/.well-known/openid-configuration` | OAuth 2.1 Discovery             |
| `/.well-known/jwks`                 | JSON Web Key Set                |
| `/connect/token`                    | Token endpoint                  |
| `/connect/authorize`                | Authorization endpoint          |
| `/connect/introspect`               | Token introspection (RFC 7662)  |
| `/connect/revocation`               | Token revocation (RFC 7009)     |
| `/connect/device_authorization`     | Device authorization (RFC 8628) |
| `/connect/device_verify`            | Device code verification        |
| `/health`                           | Health check                    |

### Running the Admin API

```bash
cd src/EasilyNET.IdentityServer.Admin.Api
dotnet run
```

The Admin API runs at `https://localhost:5002` with these endpoints:

| Endpoint                                | Description                    |
| --------------------------------------- | ------------------------------ |
| `GET/POST /api/clients`                 | List/Create clients            |
| `GET/PUT/DELETE /api/clients/{id}`      | Get/Update/Delete client       |
| `GET/POST /api/apiresources`            | List/Create API resources      |
| `GET/PUT/DELETE /api/apiresources/{id}` | Get/Update/Delete API resource |
| `GET/POST /api/apiscopes`               | List/Create API scopes         |
| `DELETE /api/apiscopes/{id}`            | Delete API scope               |
| `GET/POST /api/identityresources`       | List/Create identity resources |
| `DELETE /api/identityresources/{id}`    | Delete identity resource       |

### Running the Admin Frontend

```bash
cd src/EasilyNET.IdentityServer.Admin

# Install dependencies
bun install   # or pnpm install

# Start development server
bun run dev

# Build for production
bun run build
```

The frontend runs at `http://localhost:8000` (configurable in `.umirc.ts`).

## Configuration

### IdentityServer Options (Program.cs)

```csharp
builder.Services.AddIdentityServer(options =>
{
    options.Issuer = "https://localhost:5001";
    options.AccessTokenLifetime = 3600;      // 1 hour
    options.RefreshTokenLifetime = 86400;   // 24 hours
    options.AuthorizationCodeLifetime = 300; // 5 minutes
    options.RequirePkce = true;
    options.RequireConsent = false;
});
```

### Database Configuration

#### SQLite (Default for Admin.Api)

```csharp
services.AddIdentityServerSqlite("Data Source=identityserver.db");
```

#### SQL Server

```csharp
services.AddIdentityServerSqlServer("Server=.;Database=IdentityServer;Trusted_Connection=True");
```

#### PostgreSQL

```csharp
services.AddIdentityServerPostgreSql("Host=localhost;Database=IdentityServer;Username=postgres;Password=password");
```

#### MySQL

```csharp
services.AddIdentityServerMySql("Server=localhost;Database=IdentityServer;User=root;Password=password", ServerVersion.AutoDetect(connectionString));
```

## Design Philosophy

### 1. Modular Architecture

The project follows clean architecture principles with clear separation of concerns:

- **Abstractions** define contracts (interfaces) without implementation
- **Core** implements business logic
- **DataAccess** provides pluggable storage backends

### 2. Database Provider Pattern

Instead of bundling all database providers in one package, we provide separate NuGet packages:

- `EasilyNET.IdentityServer.DataAccess.EFCore` - Core EF Core (entities, DbContext)
- `EasilyNET.IdentityServer.DataAccess.EFCore.SqlServer` - SQL Server support
- `EasilyNET.IdentityServer.DataAccess.EFCore.Sqlite` - SQLite support
- `EasilyNET.IdentityServer.DataAccess.EFCore.PostgreSQL` - PostgreSQL support
- `EasilyNET.IdentityServer.DataAccess.EFCore.MySQL` - MySQL support

Users install only what they need, avoiding unnecessary dependencies.

### 3. Development-Friendly Defaults

- **In-Memory Stores** - The Host project uses in-memory stores for quick development
- **SQLite for Admin** - Admin API defaults to SQLite for zero-configuration startup
- **OpenAPI** - Automatic API documentation in development mode

### 4. Security-First

- **PKCE Mandatory** - Authorization Code flow requires PKCE
- **Secure Token Storage** - Refresh tokens are stored in database
- **Client Secret Validation** - Supports plaintext and SHA256-hashed secrets
- **Token Expiration** - Configurable token lifetimes

### 5. Testability

- 17 integration tests covering all OAuth endpoints
- Clean service interfaces for mocking
- WebApplicationFactory for full integration testing

## OAuth 2.1 Flows

### Client Credentials Flow

```bash
# Request token
curl -X POST https://localhost:5001/connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=console" \
  -d "client_secret=secret" \
  -d "scope=api1"

# Response
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Authorization Code Flow (PKCE)

```bash
# Step 1: Authorization Request
GET /connect/authorize?
  response_type=code&
  client_id=spa&
  redirect_uri=http://localhost:3000/callback&
  scope=openid profile&
  code_challenge=...&
  code_challenge_method=S256

# Step 2: Token Request
POST /connect/token
  grant_type=authorization_code
  code=...
  redirect_uri=http://localhost:3000/callback
  code_verifier=...
```

### Device Flow (RFC 8628)

```bash
# Step 1: Device Authorization
POST /connect/device_authorization
  client_id=device
  scope=openid profile

# Response
{
  "device_code": "...",
  "user_code": "ABCD-1234",
  "verification_uri": "https://localhost:5001/device",
  "verification_uri_complete": "https://localhost:5001/device?user_code=ABCD-1234",
  "expires_in": 300,
  "interval": 5
}

# Step 2: User authorizes (via browser)

# Step 3: Token Request
POST /connect/token
  grant_type=urn:ietf:params:oauth:grant-type:device_code
  device_code=...
  client_id=device
```

## Example Clients

The project includes pre-configured demo clients:

| Client ID | Type         | Grant Types                       | Purpose            |
| --------- | ------------ | --------------------------------- | ------------------ |
| `console` | Confidential | client_credentials                | Machine-to-machine |
| `mvc`     | Confidential | authorization_code, refresh_token | Web application    |
| `spa`     | Public       | authorization_code                | Single-page app    |
| `device`  | Public       | device_code                       | IoT devices        |

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

MIT License - see LICENSE file for details.
