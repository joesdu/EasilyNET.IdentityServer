namespace EasilyNET.IdentityServer.Abstractions.Models;

/// <summary>
/// 签名密钥模型
/// </summary>
public class SigningKey
{
    /// <summary>
    /// 密钥算法 (RS256, ES256 等)
    /// </summary>
    public string Algorithm { get; init; } = "RS256";

    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// 禁用时间
    /// </summary>
    public DateTime? DisabledAt { get; init; }

    /// <n IPS 公钥（用于 JWKS）
    /// </summary>
    public string? Exponent { get; init; }

    /// <summary>
    /// 是否已禁用
    /// </summary>
    public bool IsDisabled => DisabledAt.HasValue;

    /// <summary>
    /// 密钥 ID
    /// </summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// RSA 模数（用于 JWKS）
    /// </summary>
    public string? Modulus { get; init; }

    /// <summary>
    /// 私钥（加密存储）
    /// </summary>
    public required string PrivateKey { get; init; }

    /// <summary>
    /// 密钥用途 (signing, encryption)
    /// </summary>
    public string Usage { get; init; } = "sig";
}
