namespace EasilyNET.IdentityServer.DataAccess.EFCore.Entities;

/// <summary>
/// 签名密钥实体
/// </summary>
public class SigningKeyEntity
{
    /// <summary>
    /// 密钥算法
    /// </summary>
    public string Algorithm { get; set; } = "RS256";

    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 禁用时间
    /// </summary>
    public DateTime? DisabledAt { get; set; }

    /// <summary>
    /// RSA 指数
    /// </summary>
    public string? Exponent { get; set; }

    /// <summary>
    /// 主键
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// 是否已禁用
    /// </summary>
    public bool IsDisabled => DisabledAt.HasValue;

    /// <summary>
    /// 密钥 ID
    /// </summary>
    public required string KeyId { get; set; }

    /// <summary>
    /// RSA 模数
    /// </summary>
    public string? Modulus { get; set; }

    /// <summary>
    /// 私钥（应加密存储）
    /// </summary>
    public required string PrivateKey { get; set; }

    /// <summary>
    /// 密钥用途
    /// </summary>
    public string Usage { get; set; } = "sig";
}
