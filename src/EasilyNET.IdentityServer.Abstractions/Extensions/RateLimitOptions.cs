namespace EasilyNET.IdentityServer.Abstractions.Extensions;

/// <summary>
/// 速率限制配置选项
/// </summary>
public class RateLimitOptions
{
    /// <summary>
    /// 是否启用速率限制
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// IP 级别限制规则
    /// </summary>
    public List<RateLimitRuleConfig> IpLimits { get; set; } = new()
    {
        new()
        {
            EndpointPattern = "/connect/token",
            WindowSeconds = 60,
            MaxRequests = 60
        },
        new()
        {
            EndpointPattern = "/connect/authorize",
            WindowSeconds = 60,
            MaxRequests = 30
        },
        new()
        {
            EndpointPattern = "/connect/device_authorization",
            WindowSeconds = 60,
            MaxRequests = 10
        },
        new()
        {
            EndpointPattern = "*",
            WindowSeconds = 60,
            MaxRequests = 120
        }
    };

    /// <summary>
    /// 客户端级别限制规则
    /// </summary>
    public List<RateLimitRuleConfig> ClientLimits { get; set; } = new()
    {
        new()
        {
            EndpointPattern = "/connect/token",
            WindowSeconds = 60,
            MaxRequests = 30
        },
        new()
        {
            EndpointPattern = "/connect/authorize",
            WindowSeconds = 60,
            MaxRequests = 20
        }
    };

    /// <summary>
    /// 白名单IP列表（不受限制）
    /// </summary>
    public List<string> WhitelistIps { get; set; } = new();

    /// <summary>
    /// 白名单客户端列表
    /// </summary>
    public List<string> WhitelistClients { get; set; } = new();

    /// <summary>
    /// 是否包含响应头
    /// </summary>
    public bool IncludeHeaders { get; set; } = true;

    /// <summary>
    /// 存储清理间隔（分钟）
    /// </summary>
    public int CleanupIntervalMinutes { get; set; } = 10;
}

/// <summary>
/// 速率限制规则配置
/// </summary>
public class RateLimitRuleConfig
{
    /// <summary>
    /// 端点路径模式（* 表示通配符）
    /// </summary>
    public string EndpointPattern { get; set; } = "*";

    /// <summary>
    /// 时间窗口（秒）
    /// </summary>
    public int WindowSeconds { get; set; } = 60;

    /// <summary>
    /// 最大请求数
    /// </summary>
    public int MaxRequests { get; set; } = 100;
}
