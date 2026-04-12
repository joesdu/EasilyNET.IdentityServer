# EasilyNET.IdentityServer

> 轻量级、OAuth 2.1 兼容的身份认证服务器，基于 .NET 11 构建

[English](./README.md) | [中文](./README.zh-CN.md)

## 特性

- **OAuth 2.1 兼容** - 完整实现 OAuth 2.1 规范
- **多种授权模式** - Client Credentials、Authorization Code (PKCE)、Refresh Token、Device Flow
- **多数据库支持** - SQLite、SQL Server、PostgreSQL、MySQL（模块化包）
- **JWT 令牌** - 原生 JWT 访问令牌，HMAC-SHA256 签名
- **OpenID Connect 就绪** - Discovery 文档、JWKS 端点
- **管理 API** - 用于管理客户端、API 资源、作用域的 RESTful API
- **管理前端** - 基于 React + Umi + Ant Design 的管理界面
- **集成测试** - 17 个全面覆盖所有端点的测试用例

## 项目架构

```
┌─────────────────────────────────────────────────────────────┐
│                      解决方案分层                            │
├─────────────────────────────────────────────────────────────┤
│  执行层        │  Host (OAuth 服务器)  │  Admin.Api         │
├────────────────┼────────────────────────────────────────────┤
│  业务逻辑层    │  Core (Token、Auth、Client Auth)            │
├────────────────┼────────────────────────────────────────────┤
│  契约层        │  Abstractions                               │
├────────────────┼────────────────────────────────────────────┤
│  持久化层      │  DataAccess.EFCore (模块化)                 │
│                │  DataAccess.MongoDB                         │
└─────────────────────────────────────────────────────────────┘
```

### 项目结构

| 项目                      | 用途                                                 |
| ------------------------- | ---------------------------------------------------- |
| `Abstractions`            | 模型、服务接口、存储接口、配置选项                   |
| `Core`                    | Token 签发、客户端认证、授权服务                     |
| `DataAccess.Abstractions` | 数据库上下文契约                                     |
| `DataAccess.EFCore`       | EF Core 实体、DbContext、Stores（核心）              |
| `DataAccess.EFCore.*`     | 数据库特定包（SqlServer、Sqlite、PostgreSQL、MySQL） |
| `DataAccess.MongoDB`      | MongoDB 存储实现                                     |
| `Host`                    | OAuth 2.1 端点、开发用内存存储                       |
| `Admin.Api`               | 管理资源的 CRUD API                                  |
| `Admin`                   | React/Umi 管理前端                                   |
| `IntegrationTests`        | 端到端测试套件                                       |

## 快速开始

### 前置要求

- .NET 11 SDK
- bun 1.3.12（用于前端）
- bun（用于前端包管理）

### 后端设置

```bash
# 克隆仓库
git clone https://github.com/your-org/EasilyNET.IdentityServer.git
cd EasilyNET.IdentityServer

# 构建解决方案
dotnet build src/EasilyNET.IdentityServer.slnx

# 运行集成测试
dotnet test tests/EasilyNET.IdentityServer.IntegrationTests
```

### 运行 OAuth 服务器（Host）

```bash
cd src/EasilyNET.IdentityServer.Host
dotnet run
```

服务器运行在 `https://localhost:5001`，包含以下端点：

| 端点                                | 描述                  |
| ----------------------------------- | --------------------- |
| `/.well-known/openid-configuration` | OAuth 2.1 Discovery   |
| `/.well-known/jwks`                 | JSON Web Key Set      |
| `/connect/token`                    | Token 端点            |
| `/connect/authorize`                | 授权端点              |
| `/connect/introspect`               | Token 内省 (RFC 7662) |
| `/connect/revocation`               | Token 撤销 (RFC 7009) |
| `/connect/device_authorization`     | 设备授权 (RFC 8628)   |
| `/connect/device_verify`            | 设备码验证            |
| `/health`                           | 健康检查              |

### 运行管理 API

```bash
cd src/EasilyNET.IdentityServer.Admin.Api
dotnet run
```

管理 API 运行在 `https://localhost:5002`，包含以下端点：

| 端点                                    | 描述                    |
| --------------------------------------- | ----------------------- |
| `GET/POST /api/clients`                 | 列出/创建客户端         |
| `GET/PUT/DELETE /api/clients/{id}`      | 获取/更新/删除客户端    |
| `GET/POST /api/apiresources`            | 列出/创建 API 资源      |
| `GET/PUT/DELETE /api/apiresources/{id}` | 获取/更新/删除 API 资源 |
| `GET/POST /api/apiscopes`               | 列出/创建 API 作用域    |
| `DELETE /api/apiscopes/{id}`            | 删除 API 作用域         |
| `GET/POST /api/identityresources`       | 列出/创建身份资源       |
| `DELETE /api/identityresources/{id}`    | 删除身份资源            |

### 运行管理前端

```bash
cd src/EasilyNET.IdentityServer.Admin

# 安装依赖
bun install   # 或 pnpm install

# 启动开发服务器
bun run dev

# 生产构建
bun run build
```

前端运行在 `http://localhost:8000`（可在 `.umirc.ts` 中配置）。

## 配置

### IdentityServer 选项 (Program.cs)

```csharp
builder.Services.AddIdentityServer(options =>
{
    options.Issuer = "https://localhost:5001";
    options.AccessTokenLifetime = 3600;      // 1 小时
    options.RefreshTokenLifetime = 86400;   // 24 小时
    options.AuthorizationCodeLifetime = 300; // 5 分钟
    options.RequirePkce = true;
    options.RequireConsent = false;
});
```

### 数据库配置

#### SQLite（Admin.Api 默认）

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

## 设计理念

### 1. 模块化架构

项目遵循清晰架构原则，关注点分离明确：

- **Abstractions** 定义契约（接口）而不包含实现
- **Core** 实现业务逻辑
- **DataAccess** 提供可插拔的存储后端

### 2. 数据库提供者模式

我们将所有数据库提供者打包在一个包中，改为提供独立的 NuGet 包：

- `EasilyNET.IdentityServer.DataAccess.EFCore` - 核心 EF Core（实体、DbContext）
- `EasilyNET.IdentityServer.DataAccess.EFCore.SqlServer` - SQL Server 支持
- `EasilyNET.IdentityServer.DataAccess.EFCore.Sqlite` - SQLite 支持
- `EasilyNET.IdentityServer.DataAccess.EFCore.PostgreSQL` - PostgreSQL 支持
- `EasilyNET.IdentityServer.DataAccess.EFCore.MySQL` - MySQL 支持

用户只需安装需要的包，避免引入不必要的依赖。

### 3. 开发友好

- **内存存储** - Host 项目使用内存存储便于快速开发
- **SQLite 用于管理** - Admin API 默认使用 SQLite，无需配置即可启动
- **OpenAPI** - 开发模式自动生成 API 文档

### 4. 安全优先

- **强制 PKCE** - Authorization Code 流程必须使用 PKCE
- **安全的令牌存储** - Refresh Token 存储在数据库中
- **客户端密钥验证** - 支持明文和 SHA256 哈希的密钥
- **令牌过期** - 可配置的令牌生命周期

### 5. 可测试性

- 17 个覆盖所有 OAuth 端点的集成测试
- 清晰的服务接口便于 Mock
- WebApplicationFactory 用于完整集成测试

## OAuth 2.1 流程

### Client Credentials 流程

```bash
# 请求 Token
curl -X POST https://localhost:5001/connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=console" \
  -d "client_secret=secret" \
  -d "scope=api1"

# 响应
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Authorization Code 流程 (PKCE)

```bash
# 步骤 1: 授权请求
GET /connect/authorize?
  response_type=code&
  client_id=spa&
  redirect_uri=http://localhost:3000/callback&
  scope=openid profile&
  code_challenge=...&
  code_challenge_method=S256

# 步骤 2: Token 请求
POST /connect/token
  grant_type=authorization_code
  code=...
  redirect_uri=http://localhost:3000/callback
  code_verifier=...
```

### Device Flow (RFC 8628)

```bash
# 步骤 1: 设备授权
POST /connect/device_authorization
  client_id=device
  scope=openid profile

# 响应
{
  "device_code": "...",
  "user_code": "ABCD-1234",
  "verification_uri": "https://localhost:5001/device",
  "verification_uri_complete": "https://localhost:5001/device?user_code=ABCD-1234",
  "expires_in": 300,
  "interval": 5
}

# 步骤 2: 用户授权（通过浏览器）

# 步骤 3: Token 请求
POST /connect/token
  grant_type=urn:ietf:params:oauth:grant-type:device_code
  device_code=...
  client_id=device
```

## 示例客户端

项目包含预配置的演示客户端：

| Client ID | 类型       | 授权模式                          | 用途       |
| --------- | ---------- | --------------------------------- | ---------- |
| `console` | 机密客户端 | client_credentials                | 机器间通信 |
| `mvc`     | 机密客户端 | authorization_code, refresh_token | Web 应用   |
| `spa`     | 公开客户端 | authorization_code                | 单页应用   |
| `device`  | 公开客户端 | device_code                       | IoT 设备   |

## 贡献

欢迎贡献！提交 PR 前请阅读贡献指南。

## 许可证

MIT 许可证 - 详见 LICENSE 文件。
