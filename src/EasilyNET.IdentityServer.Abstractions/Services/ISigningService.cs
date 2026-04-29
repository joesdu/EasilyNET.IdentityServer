using Microsoft.IdentityModel.Tokens;

namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// 签名服务接口
/// </summary>
public interface ISigningService
{
    /// <summary>
    /// 获取当前活动签名密钥
    /// </summary>
    Task<SigningKeyResult> GetSigningKeyAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取所有有效签名密钥（用于 JWKS）
    /// </summary>
    Task<IEnumerable<SigningKeyResult>> GetAllSigningKeysAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 轮换签名密钥
    /// </summary>
    Task RotateKeysAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// 签名密钥结果
/// </summary>
public class SigningKeyResult
{
    /// <summary>
    /// 签名算法
    /// </summary>
    public string Algorithm { get; init; } = "RS256";

    /// <summary>
    /// 签名凭证
    /// </summary>
    public SigningCredentials Credentials { get; init; } = default!;

    /// <summary>
    /// 是否已禁用
    /// </summary>
    public bool IsDisabled { get; init; }

    /// <summary>
    /// 密钥 ID
    /// </summary>
    public string KeyId { get; init; } = default!;

    /// <summary>
    /// 安全密钥
    /// </summary>
    public SecurityKey Key { get; init; } = default!;
}
