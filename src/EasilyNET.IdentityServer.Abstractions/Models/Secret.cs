namespace EasilyNET.IdentityServer.Abstractions.Models;

/// <summary>
/// 客户端密钥
/// </summary>
public class Secret
{
    /// <summary>
    /// 密钥值
    /// </summary>
    public required string Value { get; init; }

    /// <summary>
    /// 描述
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// 过期时间
    /// </summary>
    public DateTime? Expiration { get; init; }

    /// <summary>
    /// 类型
    /// </summary>
    public string Type { get; init; } = "SharedSecret";
}

/// <summary>
/// 客户端声明
/// </summary>
public class ClientClaim
{
    /// <summary>
    /// 类型
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// 值
    /// </summary>
    public required string Value { get; init; }
}