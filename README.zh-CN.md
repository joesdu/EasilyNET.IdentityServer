# EasilyNET.IdentityServer

> 面向 .NET 11 的轻量级 OAuth 2.1 / OpenID Connect 服务器，内置现代客户端认证能力、交互式授权流程与管理后台。

[English](./README.md) | [中文](./README.zh-CN.md)

## 项目简介

`EasilyNET.IdentityServer` 是一个分层实现的身份服务仓库，围绕 OAuth 2.1 时代的默认安全实践构建：

- 授权码模式强制 PKCE
- Refresh Token 轮换与重放防护
- Client Credentials 与 Device Authorization Grant
- OpenID Connect Discovery、JWKS、`userinfo`
- 动态客户端注册
- `private_key_jwt`、mTLS、DPoP 等现代客户端认证能力

仓库中还包含：

- 基于 EF Core 的管理 API
- 基于 React + Umi + Ant Design 的管理前端
- 覆盖协议行为、安全规则与基础设施服务的集成测试和单元测试
- 位于 `docs/` 下的 OAuth 2.1 草案中文翻译

## 亮点能力

- **OAuth 2.1 风格默认值**：强制 PKCE、不实现隐式模式、默认采用刷新令牌轮换。
- **OpenID Connect 端点**：Discovery、JWKS、结束会话元数据与 `userinfo`。
- **交互式授权流程**：通过专用交互端点支持登录、`select_account` 与同意页续流。
- **高级客户端认证**：支持 `client_secret_basic`、`client_secret_post`、`private_key_jwt`、`tls_client_auth`、`self_signed_tls_client_auth`，并在适用场景下支持公开客户端。
- **DPoP 支持**：可签发并校验 DPoP 绑定访问令牌。
- **动态客户端注册**：`/connect/register` 提供 RFC 7591 风格的注册能力。
- **资源侧令牌校验**：`/connect/verify` 供资源服务器按 RFC 6750 风格验证 Bearer / DPoP 令牌。
- **运行时防护**：内置速率限制、审计日志、转发客户端证书处理与安全响应头。
- **可插拔持久化**：提供抽象层，并实现 EF Core 与 MongoDB 存储。
- **配套管理工具**：提供客户端与资源管理 API，以及 Web 管理界面。

## 解决方案结构

```
┌─────────────────────────────────────────────────────────────┐
│                      解决方案分层                            │
├─────────────────────────────────────────────────────────────┤
│  应用层        │ Host │ Admin.Api │ Admin UI                │
├────────────────┼────────────────────────────────────────────┤
│  核心层        │ Token、认证、交互、安全能力               │
├────────────────┼────────────────────────────────────────────┤
│  抽象层        │ 模型、接口、配置选项                      │
├────────────────┼────────────────────────────────────────────┤
│  持久化层      │ EF Core Providers │ MongoDB               │
└─────────────────────────────────────────────────────────────┘
```

### 主要项目

| 项目                                                   | 用途                                                                        |
| ------------------------------------------------------ | --------------------------------------------------------------------------- |
| `src/EasilyNET.IdentityServer.Abstractions`            | 领域模型、存储接口、服务契约、配置选项                                      |
| `src/EasilyNET.IdentityServer.Core`                    | Token 签发/验证、客户端认证、授权交互、DPoP、mTLS、动态注册、审计与速率限制 |
| `src/EasilyNET.IdentityServer.DataAccess.Abstractions` | 持久化抽象契约                                                              |
| `src/EasilyNET.IdentityServer.DataAccess.EFCore`       | EF Core 实体、DbContext 与 Store 实现                                       |
| `src/EasilyNET.IdentityServer.DataAccess.EFCore.*`     | 数据库特定的 EF Core Provider 包                                            |
| `src/EasilyNET.IdentityServer.DataAccess.MongoDB`      | MongoDB Store 实现                                                          |
| `src/EasilyNET.IdentityServer.Host`                    | 基于内存开发存储的 OAuth/OIDC Host                                          |
| `src/EasilyNET.IdentityServer.Admin.Api`               | 客户端与资源管理 API                                                        |
| `src/EasilyNET.IdentityServer.Admin`                   | React/Umi 管理后台与授权交互页面                                            |
| `tests/EasilyNET.IdentityServer.IntegrationTests`      | 端到端协议测试                                                              |
| `tests/EasilyNET.IdentityServer.Core.Tests`            | Core 服务单元测试                                                           |

## 已实现的协议面

### Host 公开端点

当前实现中，Host 暴露的主要端点如下：

| 端点                                                  | 用途                               | 其他                    |
| ----------------------------------------------------- | ---------------------------------- | ----------------------- |
| `GET /.well-known/openid-configuration`               | Discovery 元数据                   |
| `GET /.well-known/jwks`                               | JSON Web Key Set                   |
| `GET /connect/authorize`                              | 授权端点                           |
| `GET /connect/authorize/context/{requestId}`          | 获取授权交互上下文                 |
| `GET /connect/authorize/interaction/page/{requestId}` | 稳定交互入口，重定向到前端交互页面 |
| `POST /connect/authorize/interaction`                 | 继续执行登录 / 选账号 / 同意交互   |
| `POST /connect/token`                                 | Token 端点                         |
| `GET                                                  | POST /connect/userinfo`            | OpenID Connect UserInfo |
| `POST /connect/introspect`                            | Token 内省                         |
| `POST /connect/revocation`                            | Token 撤销                         |
| `POST /connect/register`                              | 动态客户端注册                     |
| `POST /connect/device_authorization`                  | 设备授权                           |
| `POST /connect/device_verify`                         | 简化版设备用户码确认               |
| `POST /connect/verify`                                | 面向资源服务器的访问令牌验证       |
| `GET /health`                                         | 健康检查                           |

### 已支持的授权与交互模式

- `authorization_code` + PKCE
- `refresh_token`
- `client_credentials`
- `urn:ietf:params:oauth:grant-type:device_code`
- 用户未登录时返回交互式授权续流协议
- 支持 `prompt=login`、`prompt=consent`、`prompt=select_account`
- 支持 Remember Consent 与客户端级 prompt 限制
- 支持针对客户端的 Identity Provider 限制

### 已支持的客户端认证方式

- `client_secret_basic`
- `client_secret_post`
- `private_key_jwt`
- `tls_client_auth`
- `self_signed_tls_client_auth`
- 公开客户端场景下的 `none`

## 快速开始

### 前置要求

- .NET 11 SDK / 预览工具链
- bun 1.3.x（管理前端）

### 在仓库根目录构建

```bash
dotnet build EasilyNET.IdentityServer.slnx -v minimal
```

### 运行集成测试

```bash
dotnet test tests/EasilyNET.IdentityServer.IntegrationTests/EasilyNET.IdentityServer.IntegrationTests.csproj -v minimal
```

### 运行 Host

```bash
cd src/EasilyNET.IdentityServer.Host
dotnet run
```

开发启动配置下，Host 默认监听：

- `https://localhost:7020`
- `http://localhost:5093`

当前配置的 `Issuer` 为 `https://localhost:7020`。

### 运行 Admin API

```bash
cd src/EasilyNET.IdentityServer.Admin.Api
dotnet run
```

当前开发启动配置中，Admin API 默认暴露在：

- `http://localhost:5104`

启动时会自动执行 EF Core Migration；当未提供连接字符串时，默认使用 SQLite。

### 运行管理前端

```bash
cd src/EasilyNET.IdentityServer.Admin
bun install
bun run start
```

常用前端脚本：

```bash
bun run build
bun run preview
```

前端基于 `@umijs/max` 与 Ant Design，既包含资源管理后台，也包含交互式授权流程所使用的 `/authorize/interaction` 页面。

## 管理 API 能力

当前管理 API 覆盖以下资源类型：

### 客户端管理

- 列表、创建、更新、删除客户端
- 配置 Grant Types、Scopes、Redirect URIs、CORS Origins
- 配置 Prompt 限制与 Identity Provider 限制
- 配置 Token 生命周期、Consent 行为、PKCE / Client Secret 约束

### API 资源管理

- 列表、创建、更新、删除 API Resource
- 维护关联 Scope 与 User Claims

### API 作用域管理

- 列表、创建、删除 API Scope
- 配置 `required`、`emphasize` 与 User Claims

### Identity 资源管理

- 列表、创建、删除 Identity Resource
- 配置 `required`、`emphasize`、Discovery 可见性与 User Claims

## 当前开发默认值

### Host 默认配置

示例 Host 为本地开发预置了：

- 内存版 Client、Resource、Persisted Grant、Device Code、Signing Key 与 Audit Log 存储
- `Issuer = https://localhost:7020`
- Access Token 生命周期 `3600` 秒
- Refresh Token 生命周期 `86400` 秒
- Authorization Code 生命周期 `300` 秒
- 强制 PKCE
- 示例 Host 全局默认关闭 Consent，但特定示例客户端仍可单独要求 Consent
- `IdentityServerOptions` 默认开启 DPoP、动态客户端注册、mTLS 与 `private_key_jwt`

### 示例内存客户端

开发 Host 启动时会预置一组演示客户端：

| Client ID           | 类型       | 用途                               |
| ------------------- | ---------- | ---------------------------------- |
| `console`           | 机密客户端 | Client Credentials                 |
| `mvc`               | 机密客户端 | Authorization Code + Refresh Token |
| `spa`               | 公开客户端 | 基于 PKCE 的 SPA 登录              |
| `interactive`       | 公开客户端 | 演示交互式 Consent 流程            |
| `restricted-github` | 公开客户端 | 演示 Identity Provider 限制        |
| `prompt-restricted` | 公开客户端 | 演示 Prompt 限制                   |
| `device`            | 公开客户端 | Device Authorization Grant         |

## 安全与协议行为

当前实现中已具备一些值得在 README 明确点名的安全特性：

- Refresh Token 轮换，以及 Refresh Token Family 重放后整族失效
- Authorization Code 重放检测，重放后撤销此前签发的令牌
- 速率限制、响应头配额信息与 `429` 处理
- 授权响应上的点击劫持防护与安全响应头
- 资源访问失败时返回符合 RFC 6750 风格的 `WWW-Authenticate`
- 支持经由反向代理转发客户端证书用于 mTLS 认证
- Token 端点与资源端点均执行 DPoP 证明校验
- 对 `userinfo` 等协议活动写入审计日志

## 测试覆盖

仓库中的自动化测试当前覆盖：

- Discovery 元数据与 JWKS
- Client Credentials、Authorization Code、Refresh Token、Device Flow
- 交互式登录、账号选择与同意续流
- Introspection、Revocation 与资源侧令牌校验
- 动态客户端注册
- `private_key_jwt`、mTLS 与 DPoP
- 速率限制行为
- Secret Hash、Client Authentication、Audit、Rate Limit 等 Core 服务

## 相关文档

- `docs/`：`draft-ietf-oauth-v2-1-15` 中文翻译
- `OAUTH_IMPLEMENTATION_STATUS.md`、`IMPLEMENTATION_SUMMARY.md`：仓库内实现状态与阶段性总结

## 许可证

MIT License，详见 `LICENSE`。
