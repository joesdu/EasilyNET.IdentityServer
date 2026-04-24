# CODEBUDDY.md This file provides guidance to CodeBuddy when working with code in this repository.

## Common Commands

### Build
```bash
# Build the entire solution
dotnet build src/EasilyNET.IdentityServer.slnx

# Build a specific project
dotnet build src/EasilyNET.IdentityServer.Host
```

### Test
```bash
# Run all integration tests
dotnet test tests/EasilyNET.IdentityServer.IntegrationTests

# Run a single test method
dotnet test tests/EasilyNET.IdentityServer.IntegrationTests --filter "FullyQualifiedName~IdentityServerTests.ClientCredentials_ValidClient_ReturnsAccessToken"
```

### Run
```bash
# Run the OAuth Host server (https://localhost:7020)
cd src/EasilyNET.IdentityServer.Host && dotnet run

# Run the Admin API (https://localhost:5002)
cd src/EasilyNET.IdentityServer.Admin.Api && dotnet run

# Run the Admin frontend (http://localhost:8000)
cd src/EasilyNET.IdentityServer.Admin && bun run dev
```

### Frontend (Admin)
```bash
cd src/EasilyNET.IdentityServer.Admin

# Install dependencies
bun install

# Development server
bun run dev

# Production build
bun run build:prod

# Preview production build
bun run preview
```

## Architecture

### Solution Structure
The solution follows clean architecture with four logical layers:

```
┌─────────────────────────────────────────────────────┐
│  Executable   │  Host (OAuth Server)  │  Admin.Api  │
├───────────────┼─────────────────────────────────────┤
│  Business     │  Core (Token, Auth, Client Auth)    │
├───────────────┼─────────────────────────────────────┤
│  Contracts    │  Abstractions                       │
├───────────────┼─────────────────────────────────────┤
│  Persistence   │  DataAccess.EFCore (modular)       │
└─────────────────────────────────────────────────────┘
```

### Project Responsibilities

**Abstractions** - Models and interfaces without implementation:
- `Models/` - Core domain models: `Client.cs`, `PersistedGrant.cs`, `Resources.cs`, `Secret.cs`
- `Services/` - Service interfaces: `ITokenService`, `IClientAuthenticationService`, `ISerializationService`
- `Stores/` - Storage interfaces: `IClientStore`, `IPersistedGrantStore`, `IDeviceFlowStore`, `IResourceStore`
- `Extensions/IdentityServerOptions.cs` - Configuration options (token lifetimes, PKCE requirements, etc.)

**Core** - Business logic implementation:
- `Services/TokenService.cs` - JWT access token generation with HMAC-SHA256
- `Services/AuthorizationService.cs` - Authorization code flow logic
- `Services/ClientAuthenticationService.cs` - Client credential validation
- `Services/SerializationService.cs` - Token claim serialization

**DataAccess** - Pluggable persistence backends:
- `DataAccess.EFCore/` - EF Core entities and `IdentityServerDbContext`
- `DataAccess.EFCore.{SqlServer|Sqlite|PostgreSQL|MySQL}/` - Database-specific packages
- `DataAccess.MongoDB/` - MongoDB store implementations
- `DataAccess.Abstractions/` - Database context contracts

**Host** - OAuth 2.1 server with in-memory stores for development:
- `Controllers/` - OAuth endpoints: `/connect/token`, `/connect/authorize`, `/connect/device_authorization`, etc.
- `Stores/` - In-memory implementations of `IClientStore`, `IResourceStore`, `IPersistedGrantStore`, `IDeviceFlowStore`

**Admin.Api** - RESTful CRUD API for managing IdentityServer resources (clients, scopes, resources)

**Admin** - React/Umi frontend with Ant Design Pro Components:
- `pages/Clients/` - Client management (CRUD)
- `pages/ApiResources/` - API resource management (CRUD)
- `pages/ApiScopes/` - API scope management (CRUD)
- `pages/IdentityResources/` - Identity resource management (CRUD)
- `services/api.ts` - TypeScript interfaces and API client functions

### OAuth 2.1 Grant Types Implemented
- **Client Credentials** - Machine-to-machine (`console` client)
- **Authorization Code + PKCE** - Web apps, SPAs (`mvc`, `spa` clients)
- **Refresh Token** - Token renewal with rotation
- **Device Flow (RFC 8628)** - IoT devices (`device` client)

### Demo Clients
Pre-configured in Host for testing: `console` (confidential), `mvc` (confidential), `spa` (public), `device` (public)

### Key Endpoints (Host)
- `/.well-known/openid-configuration` - OAuth 2.1 Discovery
- `/.well-known/jwks` - JSON Web Key Set
- `/connect/token` - Token endpoint
- `/connect/authorize` - Authorization endpoint
- `/connect/device_authorization` - Device authorization
- `/connect/device_verify` - Device code verification
- `/connect/introspect` - Token introspection (RFC 7662)
- `/connect/revocation` - Token revocation (RFC 7009)
- `/health` - Health check

### Dependency Injection Flow
`Program.cs` wires services via extension methods:
1. `AddIdentityServer(options)` - Registers `IdentityServerOptions` and core services
2. Stores registered as singletons (in-memory for Host, EF Core for Admin.Api)
3. Core services: `TokenService`, `ClientAuthenticationService`, `AuthorizationService`, `SerializationService`
4. `ITokenResponseGenerator` registered as transient for token response generation
