using EasilyNET.IdentityServer.Abstractions.Models;

namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// 客户端认证验证结果
/// </summary>
public sealed class ClientAuthenticationValidationResult
{
    public string? Error { get; init; }

    public string? ErrorDescription { get; init; }

    public bool IsSuccess { get; init; }
}

/// <summary>
/// private_key_jwt 客户端认证验证器
/// </summary>
public interface IJwtClientAuthenticationValidator
{
    /// <summary>
    /// 验证 JWT 客户端断言
    /// </summary>
    Task<ClientAuthenticationValidationResult> ValidateAsync(Client client, ClientAuthenticationRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// mTLS 客户端认证验证器
/// </summary>
public interface IMtlsClientAuthenticationValidator
{
    /// <summary>
    /// 验证客户端证书
    /// </summary>
    Task<ClientAuthenticationValidationResult> ValidateAsync(Client client, ClientAuthenticationRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// DPoP 校验上下文
/// </summary>
public sealed class DPoPProofValidationContext
{
    public required string HttpMethod { get; init; }

    public required string Htu { get; init; }
}

/// <summary>
/// 访问令牌校验上下文
/// </summary>
public sealed class AccessTokenValidationContext
{
    public string? DPoPProof { get; init; }

    public string? HttpMethod { get; init; }

    public string? Htu { get; init; }
}

/// <summary>
/// DPoP 证明校验结果
/// </summary>
public sealed class DPoPProofValidationResult
{
    public string? Error { get; init; }

    public string? ErrorDescription { get; init; }

    public bool IsSuccess { get; init; }

    public string? Jkt { get; init; }
}

/// <summary>
/// DPoP 服务
/// </summary>
public interface IDPoPService
{
    /// <summary>
    /// 校验 token 端点 DPoP 证明
    /// </summary>
    Task<DPoPProofValidationResult> ValidateTokenRequestAsync(string proof, DPoPProofValidationContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// 校验资源请求 DPoP 证明
    /// </summary>
    Task<DPoPProofValidationResult> ValidateResourceRequestAsync(string proof, string accessToken, string expectedJkt, DPoPProofValidationContext context, CancellationToken cancellationToken = default);
}
