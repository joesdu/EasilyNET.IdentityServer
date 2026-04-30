using System.ComponentModel.DataAnnotations;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.Entities;

/// <summary>
/// 持久化授权实体
/// </summary>
public class PersistedGrantEntity
{
    public required string ClientId { get; set; }

    public DateTime? ConsumedTime { get; set; }

    public DateTime CreationTime { get; set; }

    public required string Data { get; set; }

    public string? Description { get; set; }

    public DateTime? ExpirationTime { get; set; }

    public required string Key { get; set; }

    /// <summary>
    /// 额外属性的JSON序列化
    /// </summary>
    public string? PropertiesJson { get; set; }

    public string? SessionId { get; set; }

    public string? SubjectId { get; set; }

    public required string Type { get; set; }

    /// <summary>
    /// 并发令牌，用于乐观并发控制，防止授权码重用竞态条件
    /// </summary>
    [ConcurrencyCheck]
    public byte[]? RowVersion { get; set; }
}

/// <summary>
/// 设备代码实体
/// </summary>
public class DeviceCodeEntity
{
    public required string ClientId { get; set; }

    public DateTime CreationTime { get; set; }

    public required string Data { get; set; }

    public string? Description { get; set; }

    public required string DeviceCode { get; set; }

    public DateTime ExpirationTime { get; set; }

    public int Id { get; set; }

    /// <summary>
    /// 额外属性的JSON序列化
    /// </summary>
    public string? PropertiesJson { get; set; }

    public string? SubjectId { get; set; }

    public required string UserCode { get; set; }
}

/// <summary>
/// 用户 Consent 实体
/// </summary>
public class UserConsentEntity
{
    public required string ClientId { get; set; }

    public DateTime CreationTime { get; set; }

    public DateTime? ExpirationTime { get; set; }

    public int Id { get; set; }

    public required string Scopes { get; set; }

    public required string SubjectId { get; set; }
}
