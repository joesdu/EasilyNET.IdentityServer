using EasilyNET.IdentityServer.Abstractions.Models;

namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// Token 服务接口
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// 创建 Access Token
    /// </summary>
    Task<TokenResult> CreateAccessTokenAsync(TokenRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// 创建 Authorization Code
    /// </summary>
    Task<string> CreateAuthorizationCodeAsync(AuthorizationCodeRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// 验证 Access Token
    /// </summary>
    Task<TokenValidationResult> ValidateAccessTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// 撤销 Token
    /// </summary>
    Task RevokeAsync(string token, CancellationToken cancellationToken = default);
}

/// <summary>
/// Token 请求
/// </summary>
public class TokenRequest
{
    /// <summary>
    /// 客户端
    /// </summary>
    public required Client Client { get; init; }

    /// <summary>
    /// 授权类型
    /// </summary>
    public required string GrantType { get; init; }

    /// <summary>
    /// 作用域
    /// </summary>
    public required IEnumerable<string> Scopes { get; init; }

    /// <summary>
    /// 主题Id (用户Id)
    /// </summary>
    public string? SubjectId { get; init; }

    /// <summary>
    /// 授权码 (用于 Authorization Code 流程)
    /// </summary>
    public string? AuthorizationCode { get; init; }

    /// <summary>
    /// Refresh Token (用于 Refresh Token 流程)
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// PKCE Code Verifier
    /// </summary>
    public string? CodeVerifier { get; init; }

    /// <summary>
    /// 附加声明
    /// </summary>
    public IDictionary<string, object>? Claims { get; init; }
}

/// <summary>
/// Authorization Code 请求
/// </summary>
public class AuthorizationCodeRequest
{
    /// <summary>
    /// 客户端
    /// </summary>
    public required Client Client { get; init; }

    /// <summary>
    /// 作用域
    /// </summary>
    public required IEnumerable<string> Scopes { get; init; }

    /// <summary>
    /// 主题Id
    /// </summary>
    public required string SubjectId { get; init; }

    /// <summary>
    /// 重定向 URI
    /// </summary>
    public required string RedirectUri { get; init; }

    /// <summary>
    /// Nonce
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// 附加请求参数
    /// </summary>
    public IDictionary<string, string>? RequestParameters { get; init; }
}

/// <summary>
/// Token 结果
/// </summary>
public class TokenResult
{
    /// <summary>
    /// Access Token
    /// </summary>
    public required string AccessToken { get; init; }

    /// <summary>
    /// Token 类型
    /// </summary>
    public string TokenType { get; init; } = "Bearer";

    /// <summary>
    /// 过期时间 (秒)
    /// </summary>
    public int ExpiresIn { get; init; }

    /// <summary>
    /// Refresh Token
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// 作用域
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// 额外参数
    /// </summary>
    public IDictionary<string, string>? Extra { get; init; }
}

/// <summary>
/// Token 验证结果
/// </summary>
public class TokenValidationResult
{
    /// <summary>
    /// 是否有效
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// 错误信息
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// 错误描述
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// 客户端Id
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// 主题Id
    /// </summary>
    public string? SubjectId { get; init; }

    /// <summary>
    /// 作用域
    /// </summary>
    public IEnumerable<string>? Scopes { get; init; }

    /// <summary>
    /// 过期时间
    /// </summary>
    public DateTime? ExpirationTime { get; init; }
}