using EasilyNET.IdentityServer.Abstractions.Models;

namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// 序列化服务接口
/// </summary>
public interface ISerializationService
{
    /// <summary>
    /// 序列化对象为 JSON
    /// </summary>
    string Serialize<T>(T obj);

    /// <summary>
    /// 反序列化 JSON 为对象
    /// </summary>
    T? Deserialize<T>(string data);
}

/// <summary>
/// Profile Service 接口 - 用于加载用户声明
/// </summary>
public interface IProfileService
{
    /// <summary>
    /// 获取用户 Claims
    /// </summary>
    Task<IEnumerable<Claim>> GetProfileDataAsync(ProfileDataRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// 验证用户是否活跃
    /// </summary>
    Task<bool> IsActiveAsync(IsActiveRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Profile 数据请求
/// </summary>
public class ProfileDataRequest
{
    /// <summary>
    /// 主题Id
    /// </summary>
    public required string SubjectId { get; init; }

    /// <summary>
    /// 请求的令牌类型
    /// </summary>
    public string? TokenType { get; init; }

    /// <summary>
    /// 客户端
    /// </summary>
    public Client? Client { get; init; }

    /// <summary>
    /// 资源 (用于资源 Owner 凭证授权)
    /// </summary>
    public IEnumerable<string>? Resources { get; init; }

    /// <summary>
    /// 要求的Claims
    /// </summary>
    public IEnumerable<string>? RequestedClaims { get; init; }
}

/// <summary>
/// 是否活跃请求
/// </summary>
public class IsActiveRequest
{
    /// <summary>
    /// 主题Id
    /// </summary>
    public required string SubjectId { get; init; }

    /// <summary>
    /// 客户端
    /// </summary>
    public Client? Client { get; init; }
}

/// <summary>
/// 声明
/// </summary>
public class Claim
{
    /// <summary>
    /// 类型
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// 值
    /// </summary>
    public required string Value { get; init; }

    /// <summary>
    /// 值类型
    /// </summary>
    public string? ValueType { get; init; }
}