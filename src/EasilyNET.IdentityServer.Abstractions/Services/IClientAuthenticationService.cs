using System.Security.Cryptography.X509Certificates;
using EasilyNET.IdentityServer.Abstractions.Models;

namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// 客户端认证服务接口
/// </summary>
public interface IClientAuthenticationService
{
    /// <summary>
    /// 验证客户端
    /// </summary>
    Task<ClientAuthenticationResult> AuthenticateClientAsync(ClientAuthenticationRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// 客户端认证请求
/// </summary>
public class ClientAuthenticationRequest
{
    /// <summary>
    /// 客户端断言 (JWT)
    /// </summary>
    public string? ClientAssertion { get; init; }

    /// <summary>
    /// 客户端断言类型
    /// </summary>
    public string? ClientAssertionType { get; init; }

    /// <summary>
    /// 客户端Id
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// 客户端密钥
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// 客户端证书
    /// </summary>
    public X509Certificate2? ClientCertificate { get; init; }

    /// <summary>
    /// 授权类型
    /// </summary>
    public required string GrantType { get; init; }

    /// <summary>
    /// 请求的端点绝对地址
    /// </summary>
    public string? RequestedEndpoint { get; init; }

    /// <summary>
    /// 重定向 URI (Token 请求时)
    /// </summary>
    public string? RedirectUri { get; init; }

    /// <summary>
    /// Token 端点 URL (用于验证 JWT 断言的 aud 声明)
    /// </summary>
    public string? TokenEndpoint { get; init; }
}

/// <summary>
/// 客户端认证结果
/// </summary>
public class ClientAuthenticationResult
{
    /// <summary>
    /// 客户端
    /// </summary>
    public Client? Client { get; init; }

    /// <summary>
    /// 错误信息
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// 错误描述
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// 是否成功
    /// </summary>
    public bool IsSuccess { get; init; }
}

/// <summary>
/// 授权服务接口
/// </summary>
public interface IAuthorizationService
{
    /// <summary>
    /// 验证授权请求
    /// </summary>
    Task<AuthorizationResult> ValidateAuthorizationRequestAsync(AuthorizationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// 批准授权请求
    /// </summary>
    Task<ApprovedAuthorizationResult> ApproveAuthorizationRequestAsync(ApprovedAuthorizationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// 拒绝授权请求
    /// </summary>
    Task DenyAuthorizationRequestAsync(string requestId, CancellationToken cancellationToken = default);
}

/// <summary>
/// 授权请求上下文服务
/// </summary>
public interface IAuthorizationRequestContextService
{
    /// <summary>
    /// 存储授权请求上下文
    /// </summary>
    Task StoreAsync(AuthorizationRequestContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取授权请求上下文
    /// </summary>
    Task<AuthorizationRequestContext?> GetAsync(string requestId, CancellationToken cancellationToken = default);

    /// <summary>
    /// 删除授权请求上下文
    /// </summary>
    Task RemoveAsync(string requestId, CancellationToken cancellationToken = default);
}

/// <summary>
/// 授权请求
/// </summary>
public class AuthorizationRequest
{
    /// <summary>
    /// 客户端Id
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// PKCE Code Challenge
    /// </summary>
    public string? CodeChallenge { get; init; }

    /// <summary>
    /// PKCE Code Challenge Method
    /// </summary>
    public string? CodeChallengeMethod { get; init; }

    /// <summary>
    /// 登录提示
    /// </summary>
    public string? LoginHint { get; init; }

    /// <summary>
    /// 最大认证年龄（秒）
    /// </summary>
    public int? MaxAge { get; init; }

    /// <summary>
    /// Nonce
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// 提示
    /// </summary>
    public string? Prompt { get; init; }

    /// <summary>
    /// 重定向 URI
    /// </summary>
    public required string RedirectUri { get; init; }

    /// <summary>
    /// 响应类型
    /// </summary>
    public required string ResponseType { get; init; }

    /// <summary>
    /// 作用域
    /// </summary>
    public required IEnumerable<string> Scopes { get; init; }

    /// <summary>
    /// 状态参数
    /// </summary>
    public string? State { get; init; }
}

/// <summary>
/// 授权结果
/// </summary>
public class AuthorizationResult
{
    /// <summary>
    /// 客户端
    /// </summary>
    public Client? Client { get; init; }

    /// <summary>
    /// 错误信息
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// 错误描述
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// 是否成功
    /// </summary>
    public bool IsSuccess { get; init; }

    /// <summary>
    /// 请求有效但需要用户交互
    /// </summary>
    public bool NeedsConsent { get; init; }

    /// <summary>
    /// 需要登录
    /// </summary>
    public bool NeedsLogin { get; init; }

    /// <summary>
    /// 授权请求Id
    /// </summary>
    public string? RequestId { get; init; }
}

/// <summary>
/// 批准的授权请求
/// </summary>
public class ApprovedAuthorizationRequest
{
    /// <summary>
    /// 客户端Id
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// PKCE Code Challenge
    /// </summary>
    public string? CodeChallenge { get; init; }

    /// <summary>
    /// PKCE Code Challenge Method
    /// </summary>
    public string? CodeChallengeMethod { get; init; }

    /// <summary>
    /// Nonce
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// Remember Consent
    /// </summary>
    public bool RememberConsent { get; init; }

    /// <summary>
    /// 授权请求Id
    /// </summary>
    public required string RequestId { get; init; }

    /// <summary>
    /// 批准的作用域
    /// </summary>
    public required IEnumerable<string> Scopes { get; init; }

    /// <summary>
    /// 重定向 URI
    /// </summary>
    public required string RedirectUri { get; init; }

    /// <summary>
    /// 主题Id
    /// </summary>
    public required string SubjectId { get; init; }
}

/// <summary>
/// 持久化的授权请求上下文
/// </summary>
public class AuthorizationRequestContext
{
    /// <summary>
    /// 客户端标识
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// 客户端名称
    /// </summary>
    public string? ClientName { get; init; }

    /// <summary>
    /// 客户端主页
    /// </summary>
    public string? ClientUri { get; init; }

    /// <summary>
    /// Logo URI
    /// </summary>
    public string? LogoUri { get; init; }

    /// <summary>
    /// PKCE Code Challenge
    /// </summary>
    public string? CodeChallenge { get; init; }

    /// <summary>
    /// PKCE Code Challenge Method
    /// </summary>
    public string? CodeChallengeMethod { get; init; }

    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTime CreationTime { get; init; }

    /// <summary>
    /// 过期时间
    /// </summary>
    public DateTime ExpirationTime { get; init; }

    /// <summary>
    /// 客户端限制的 Identity Provider
    /// </summary>
    public string[] IdentityProviderRestrictions { get; init; } = [];

    /// <summary>
    /// 登录提示
    /// </summary>
    public string? LoginHint { get; init; }

    /// <summary>
    /// 最大认证年龄（秒）
    /// </summary>
    public int? MaxAge { get; init; }

    /// <summary>
    /// Nonce
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// 待批准的作用域
    /// </summary>
    public string[] PendingConsentScopes { get; init; } = [];

    /// <summary>
    /// 提示
    /// </summary>
    public string? Prompt { get; init; }

    /// <summary>
    /// 是否允许记住同意
    /// </summary>
    public bool RememberConsentAllowed { get; init; }

    /// <summary>
    /// 是否需要同意
    /// </summary>
    public bool RequiresConsent { get; init; }

    /// <summary>
    /// 重定向 URI
    /// </summary>
    public required string RedirectUri { get; init; }

    /// <summary>
    /// 请求标识
    /// </summary>
    public required string RequestId { get; init; }

    /// <summary>
    /// 当前已选中的 subjectId
    /// </summary>
    public string? SubjectId { get; init; }

    /// <summary>
    /// 当前已选中的账号展示名
    /// </summary>
    public string? SubjectDisplayName { get; init; }

    /// <summary>
    /// 当前已选中的 Identity Provider
    /// </summary>
    public string? SubjectIdentityProvider { get; init; }

    /// <summary>
    /// 请求的作用域
    /// </summary>
    public required string[] RequestedScopes { get; init; }

    /// <summary>
    /// 状态参数
    /// </summary>
    public string? State { get; init; }
}

/// <summary>
/// 批准的授权结果
/// </summary>
public class ApprovedAuthorizationResult
{
    /// <summary>
    /// Authorization Code
    /// </summary>
    public string? AuthorizationCode { get; init; }

    /// <summary>
    /// 错误信息
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// 错误描述
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// 是否成功
    /// </summary>
    public bool IsSuccess { get; init; }
}
