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
    /// 客户端Id
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// 客户端密钥
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// 授权类型
    /// </summary>
    public required string GrantType { get; init; }

    /// <summary>
    /// 重定向 URI (Token 请求时)
    /// </summary>
    public string? RedirectUri { get; init; }
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
