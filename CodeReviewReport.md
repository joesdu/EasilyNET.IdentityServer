# EasilyNET.IdentityServer 代码审查报告

**审查日期**: 2026年4月29日
**审查范围**: OAuth 2.1 协议实现合规性、安全性、数据库持久化
**参考规范**: draft-ietf-oauth-v2-1-15 + 相关 RFC 规范

---

## 执行摘要

EasilyNET.IdentityServer 是一个基于 .NET 的 OAuth 2.1 授权服务器实现。整体架构设计合理，代码结构清晰，对 OAuth 2.1 规范有较好的遵循。

**总体评分**: 8/10

### 亮点
- ✅ 核心 Grant Type 完整实现（授权码+PKCE、客户端凭证、刷新令牌、设备流）
- ✅ 数据库持久化完整（EF Core + MongoDB，支持多种数据库）
- ✅ 安全措施良好（常量时间比较、PKCE 强制、并发控制）
- ✅ 代码分层清晰，依赖注入正确使用

### 主要问题
- 🔴 **Access Token 缺少 `aud` 声明**（RFC 7.1.3.6 要求）
- 🔴 **Introspection 端点返回格式错误**（RFC 7662 要求 401 + WWW-Authenticate）
- 🟡 **点击劫持保护缺失**（X-Frame-Options, CSP headers）
- 🟡 **公开客户端刷新令牌安全机制未实现**
- 🟡 **Discovery 文档缺少多个推荐字段

---

## 一、Grant Types 实现检查 (04-grant-types)

### ✅ 1.1 授权码许可 (Authorization Code)

| 要求 | 状态 | 位置 |
|------|------|------|
| PKCE 支持 (S256/plain) | ✅ | TokenController:484-499 |
| code_challenge 强制 | ✅ | AuthorizationService:88-96 |
| 授权码单次使用 | ✅ | TokenController:133-147 |
| 授权码有效期验证 | ✅ | TokenController:142-147 |
| code_verifier 验证 | ✅ | TokenController:149-173 |
| 授权码绑定 client_id | ✅ | AuthorizationService:165 |
| 授权码绑定 code_challenge | ✅ | AuthorizationService:175 |

### ✅ 1.2 客户端凭证许可 (Client Credentials)

| 要求 | 状态 | 位置 |
|------|------|------|
| 仅限机密客户端 | ✅ | ClientAuthenticationService:71-96 |
| 客户端认证 | ✅ | TokenController:59-75 |
| scope 验证 | ✅ | TokenController:94-101 |

### ✅ 1.3 刷新令牌许可 (Refresh Token)

| 要求 | 状态 | 位置 |
|------|------|------|
| 刷新令牌轮换 | ✅ | TokenController:278-291 |
| scope 限制 | ✅ | TokenController:270-276 |
| 绝对生命周期 | ✅ | TokenController:259-268 |
| 客户端绑定验证 | ✅ | TokenController:248-252 |

**问题**: 公开客户端的刷新令牌必须是发送者约束或一次性的 (RFC 9700 4.14.2)，当前实现未区分

### ✅ 1.4 设备授权许可 (RFC 8628)

| 要求 | 状态 | 位置 |
|------|------|------|
| device_code 生成 | ✅ | DeviceAuthorizationController:142-149 |
| user_code 生成 | ✅ | DeviceAuthorizationController:151-162 |
| 轮询间隔控制 | ⚠️ | 部分实现 |
| authorization_pending | ✅ | TokenController:340-342 |
| slow_down 错误 | ✅ | TokenController:398-401 |

**问题**: `authorization_pending` 应在轮询间隔未到时返回，而不是立即返回

---

## 二、协议端点检查 (03-protocol-endpoints)

### ✅ 2.1 授权端点 `/connect/authorize`

| 要求 | 状态 | 位置 |
|------|------|------|
| response_type=code | ✅ | AuthorizationService:41-50 |
| redirect_uri 精确匹配 | ✅ | AuthorizationService:77 |
| state 参数 | ✅ | AuthorizeController:40 |
| nonce 参数 | ✅ | AuthorizeController:42 |
| code_challenge 强制 | ✅ | AuthorizationService:88-96 |
| prompt 参数 | ✅ | AuthorizeController:110-131 |
| scope 验证 | ✅ | AuthorizationService:111-127 |

**问题**: 缺少点击劫持保护头 (X-Frame-Options, CSP)

### ✅ 2.2 令牌端点 `/connect/token`

| 要求 | 状态 | 位置 |
|------|------|------|
| POST 方法 | ✅ | TokenController:48 |
| Basic Auth 支持 | ✅ | TokenController:467-478 |
| client_secret_post 支持 | ✅ | TokenController:480-481 |
| Cache-Control: no-store | ✅ | TokenController:520 |
| JSON 响应格式 | ✅ | TokenSuccessResponse |

### 🟡 2.3 Discovery 端点

**问题**: 缺少以下推荐字段
- `authorization_response_iss_parameter_supported` (RFC 9207)
- `check_iframe`
- `pushed_authorization_request_endpoint`
- `require_signed_request_object`

### 🔴 2.4 Introspection 端点 - RFC 7662

| 要求 | 状态 | 问题 |
|------|------|------|
| client_id 匹配检查 | ✅ | ✅ |

**严重问题**: RFC 7662 Section 2.2 要求无效 token 返回 **401 + WWW-Authenticate 头**，当前实现只返回 `{ active: false }` + 200

### ✅ 2.5 Revocation 端点 - RFC 7009

| 要求 | 状态 |
|------|------|
| token_type_hint 支持 | ✅ |
| 始终返回 200 | ✅ |

---

## 三、安全考虑检查 (07-security-considerations)

### ✅ 3.1 授权码安全

| 要求 | 状态 |
|------|------|
| 防止授权码注入 (PKCE) | ✅ |
| 防止授权码重用 | ✅ |
| 常量时间 Secret 比较 | ✅ |
| 并发控制 (RowVersion) | ✅ |

### 🔴 3.2 访问令牌安全

**严重问题**: Access Token 缺少 `aud` (受众) 声明

当前实现 (TokenService.cs:95):
```csharp
Audience = string.Join(" ", scopes), // 使用 scopes 作为 audience
```

规范要求 (RFC 7.1.3.6):
> 访问令牌应限制为某些资源服务器（受众限制）

### 🔴 3.3 点击劫持保护

**问题**: 授权端点缺少以下响应头
- `X-Frame-Options`
- `Content-Security-Policy` (frame-ancestors)

规范要求 (RFC 7.10):
> 授权服务器必须防止点击劫持攻击

### ⚠️ 3.4 公开客户端刷新令牌

**问题**: RFC 9700 4.14.2 要求公开客户端的刷新令牌必须是：
- 发送者约束 (DPoP/mTLS)，或
- 一次性的 (轮换)

当前实现只做了轮换，但没有对公开客户端加强安全

---

## 四、数据库持久化检查

### ✅ 4.1 EF Core 实体完整性

| 实体 | 状态 | 说明 |
|------|------|------|
| ClientEntity | ✅ | 完整，包含所有子实体 |
| PersistedGrantEntity | ✅ | 包含 RowVersion 用于并发控制 |
| DeviceCodeEntity | ✅ | 完整 |
| UserConsentEntity | ✅ | 完整 |
| ApiResourceEntity | ✅ | 完整 |
| SigningKeyEntity | ✅ | 完整 |

### ✅ 4.2 数据库索引

所有必要的索引都已配置：
- ClientId 唯一索引
- PersistedGrant 复合索引 (SubjectId, ClientId, Type)
- DeviceCode DeviceCode/UserCode 唯一索引

### ✅ 4.3 EF Core Store 实现

| Store | 状态 |
|-------|------|
| EfClientStore | ✅ |
| EfPersistedGrantStore | ✅ |
| EfDeviceFlowStore | ✅ |
| EfResourceStore | ✅ |
| EfUserConsentStore | ✅ |

### ✅ 4.4 MongoDB Store 实现

| Store | 状态 |
|-------|------|
| MongoStores | ✅ |

**注意**: `ConsumeDeviceCodeAsync` 在 MongoDB 实现中存在，需要确保接口完整性

---

## 五、问题汇总

### 🔴 严重问题 (P0)

| # | 问题 | 规范 | 影响 |
|---|------|------|------|
| 1 | Access Token 缺少 `aud` 声明 | RFC 7.1.3.6 | 令牌可用于任何资源服务器 |
| 2 | Introspection 返回格式错误 | RFC 7660 2.2 | 不符合 RFC 标准 |
| 3 | 缺少点击劫持保护 | RFC 7.10 | 授权页面可被嵌入 |

### 🟡 中等问题 (P1)

| # | 问题 | 规范 | 影响 |
|---|------|------|------|
| 4 | localhost redirect_uri 端口可变 | RFC 8252 7.3 | localhost 精确匹配可能失败 |
| 5 | Discovery 文档缺少字段 | RFC 8414 | 互操作性下降 |
| 6 | 公开客户端刷新令牌安全 | RFC 9700 4.14.2 | 安全风险 |
| 7 | 设备流轮询间隔控制 | RFC 8628 3.5 | 可能被滥用 |

### 🟢 轻微问题 (P2)

| # | 问题 | 建议 |
|---|------|------|
| 8 | device_code 验证 URI 返回 | RFC 8628 3.2 |
| 9 | plain PKCE 支持 | 限制仅开发环境使用 |
| 10 | JWKS 端点完善 | 添加更多密钥类型 |

---

## 六、代码质量评价

### ✅ 优点
1. 分层清晰：Abstractions → Core → DataAccess → Host
2. 依赖注入正确使用
3. 异步编程规范
4. 并发控制使用 RowVersion
5. 常量时间比较防时序攻击
6. 支持多种数据库后端

### ⚠️ 需改进
1. 部分魔法数字应定义为常量
2. 公开 API 缺少 XML 文档
3. 缺少单元测试覆盖检查

---

## 七、修复优先级

### 立即修复 (P0)
1. **TokenService.cs:95** - 添加 `aud` 声明
2. **IntrospectionController.cs** - 返回 401 + WWW-Authenticate
3. **AuthorizeController.cs** - 添加点击劫持保护头

### 高优先级 (P1)
4. localhost redirect_uri 端口可变逻辑
5. 完善 Discovery 文档字段
6. 设备流轮询间隔控制

### 中优先级 (P2)
7. 公开客户端刷新令牌安全增强
8. 限制 plain PKCE 使用

---

## 附录: 参考规范

1. [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15)
2. [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
3. [RFC 8628 - Device Flow](https://tools.ietf.org/html/rfc8628)
4. [RFC 7009 - Token Revocation](https://tools.ietf.org/html/rfc7009)
5. [RFC 7662 - Token Introspection](https://tools.ietf.org/html/rfc7662)
6. [RFC 8252 - Native Apps](https://tools.ietf.org/html/rfc8252)
7. [RFC 9700 - Security BCP](https://tools.ietf.org/html/rfc9700)
8. [RFC 9207 - Issuer Identification](https://tools.ietf.org/html/rfc9207)

---

**报告编制**: AI Code Review
**审查日期**: 2026-04-29
