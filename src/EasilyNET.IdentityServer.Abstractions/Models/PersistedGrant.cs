namespace EasilyNET.IdentityServer.Abstractions.Models;

/// <summary>
/// 授权类型
/// </summary>
public static class GrantType
{
    public const string AuthorizationCode = "authorization_code";
    public const string ClientCredentials = "client_credentials";
    public const string DeviceCode = "device_code";
    public const string Implicit = "implicit";
    public const string RefreshToken = "refresh_token";
}

/// <summary>
/// 持久化授权/Token 存储模型
/// </summary>
public class PersistedGrant
{
    /// <summary>
    /// 客户端Id
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// 消耗时间
    /// </summary>
    public DateTime? ConsumedTime { get; init; }

    /// <summary>
    /// 创建时间
    /// </summary>
    public required DateTime CreationTime { get; init; }

    /// <summary>
    /// 数据 (Token 数据,序列化后的JSON)
    /// </summary>
    public required string Data { get; init; }

    /// <summary>
    /// 描述
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// 过期时间
    /// </summary>
    public DateTime? ExpirationTime { get; init; }

    /// <summary>
    /// 密钥 (Token Id)
    /// </summary>
    public required string Key { get; init; }

    /// <summary>
    /// 额外的属性
    /// </summary>
    public IDictionary<string, string> Properties { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// 会话Id
    /// </summary>
    public string? SessionId { get; init; }

    /// <summary>
    /// 主题Id (用户Id)
    /// </summary>
    public string? SubjectId { get; init; }

    /// <summary>
    /// 类型
    /// </summary>
    public required string Type { get; init; }
}

/// <summary>
/// 授权过滤器
/// </summary>
public class PersistedGrantFilter
{
    /// <summary>
    /// 客户端Id
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// 会话Id
    /// </summary>
    public string? SessionId { get; init; }

    /// <summary>
    /// 主题Id
    /// </summary>
    public string? SubjectId { get; init; }

    /// <summary>
    /// 类型
    /// </summary>
    public string? Type { get; init; }
}

/// <summary>
/// 设备代码
/// </summary>
public class DeviceCodeData
{
    /// <summary>
    /// 客户端Id
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// 设备代码
    /// </summary>
    public required string Code { get; init; }

    /// <summary>
    /// 创建时间
    /// </summary>
    public required DateTime CreationTime { get; init; }

    /// <summary>
    /// 数据
    /// </summary>
    public required string Data { get; init; }

    /// <summary>
    /// 描述
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// 过期时间
    /// </summary>
    public required DateTime ExpirationTime { get; init; }

    /// <summary>
    /// 额外的属性
    /// </summary>
    public IDictionary<string, string> Properties { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// 主题Id
    /// </summary>
    public string? SubjectId { get; init; }

    /// <summary>
    /// 用户代码
    /// </summary>
    public required string UserCode { get; init; }
}

/// <summary>
/// 用户同意
/// </summary>
public class UserConsent
{
    /// <summary>
    /// 客户端Id
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// 创建时间
    /// </summary>
    public required DateTime CreationTime { get; init; }

    /// <summary>
    /// 过期时间
    /// </summary>
    public DateTime? ExpirationTime { get; init; }

    /// <summary>
    /// 允许的作用域
    /// </summary>
    public required IEnumerable<string> Scopes { get; init; }

    /// <summary>
    /// 主题Id
    /// </summary>
    public required string SubjectId { get; init; }
}