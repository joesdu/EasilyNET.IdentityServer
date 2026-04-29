namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// 速率限制服务接口
/// </summary>
public interface IRateLimitService
{
    /// <summary>
    /// 检查是否允许请求
    /// </summary>
    /// <param name="key">限制键（IP地址或客户端ID）</param>
    /// <param name="limitType">限制类型</param>
    /// <param name="cancellationToken"></param>
    /// <returns>是否允许请求</returns>
    Task<bool> IsAllowedAsync(string key, RateLimitType limitType, CancellationToken cancellationToken = default);

    /// <summary>
    /// 记录请求
    /// </summary>
    /// <param name="key">限制键</param>
    /// <param name="limitType">限制类型</param>
    /// <param name="cancellationToken"></param>
    Task RecordRequestAsync(string key, RateLimitType limitType, CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取剩余请求数
    /// </summary>
    /// <param name="key">限制键</param>
    /// <param name="limitType">限制类型</param>
    /// <param name="cancellationToken"></param>
    /// <returns>剩余请求数</returns>
    Task<int> GetRemainingRequestsAsync(string key, RateLimitType limitType, CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取重置时间
    /// </summary>
    /// <param name="key">限制键</param>
    /// <param name="limitType">限制类型</param>
    /// <param name="cancellationToken"></param>
    /// <returns>重置时间</returns>
    Task<DateTimeOffset> GetResetTimeAsync(string key, RateLimitType limitType, CancellationToken cancellationToken = default);

    /// <summary>
    /// 清除限制记录
    /// </summary>
    /// <param name="key">限制键</param>
    /// <param name="cancellationToken"></param>
    Task ClearLimitAsync(string key, CancellationToken cancellationToken = default);
}

/// <summary>
/// 速率限制类型
/// </summary>
public enum RateLimitType
{
    /// <summary>
    /// 一般端点限制
    /// </summary>
    General,

    /// <summary>
    /// Token端点限制
    /// </summary>
    TokenEndpoint,

    /// <summary>
    /// 授权端点限制
    /// </summary>
    AuthorizeEndpoint,

    /// <summary>
    /// 设备授权端点限制
    /// </summary>
    DeviceAuthorizationEndpoint,

    /// <summary>
    /// 验证端点限制
    /// </summary>
    VerifyEndpoint
}

/// <summary>
/// 速率限制规则
/// </summary>
public class RateLimitRule
{
    /// <summary>
    /// 限制类型
    /// </summary>
    public RateLimitType LimitType { get; set; }

    /// <summary>
    /// 时间窗口（秒）
    /// </summary>
    public int WindowSeconds { get; set; }

    /// <summary>
    /// 最大请求数
    /// </summary>
    public int MaxRequests { get; set; }

    /// <summary>
    /// 区块大小（用于滑动窗口）
    /// </summary>
    public int BlockSizeSeconds { get; set; } = 1;
}

/// <summary>
/// 速率限制结果
/// </summary>
public class RateLimitResult
{
    /// <summary>
    /// 是否允许
    /// </summary>
    public bool IsAllowed { get; set; }

    /// <summary>
    /// 剩余请求数
    /// </summary>
    public int Remaining { get; set; }

    /// <summary>
    /// 限制数
    /// </summary>
    public int Limit { get; set; }

    /// <summary>
    /// 重置时间
    /// </summary>
    public DateTimeOffset ResetTime { get; set; }

    /// <summary>
    /// 重试时间（秒）
    /// </summary>
    public int? RetryAfter { get; set; }
}
