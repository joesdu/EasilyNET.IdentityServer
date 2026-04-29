using EasilyNET.IdentityServer.Abstractions.Services;

namespace EasilyNET.IdentityServer.Abstractions.Stores;

/// <summary>
/// 审计日志存储接口
/// </summary>
public interface IAuditLogStore
{
    /// <summary>
    /// 存储审计事件
    /// </summary>
    Task StoreAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// 查询审计日志
    /// </summary>
    Task<IEnumerable<AuditEvent>> QueryAsync(AuditLogFilter filter, CancellationToken cancellationToken = default);

    /// <summary>
    /// 清理过期日志
    /// </summary>
    Task PurgeOldLogsAsync(DateTime cutoff, CancellationToken cancellationToken = default);
}

/// <summary>
/// 审计日志查询筛选器
/// </summary>
public class AuditLogFilter
{
    /// <summary>
    /// 客户端 ID
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// 结束时间
    /// </summary>
    public DateTime? EndTime { get; init; }

    /// <summary>
    /// 事件类型
    /// </summary>
    public string? EventType { get; init; }

    /// <summary>
    /// 最大返回数量
    /// </summary>
    public int? Limit { get; init; }

    /// <summary>
    /// 是否成功
    /// </summary>
    public bool? Success { get; init; }

    /// <summary>
    /// 开始时间
    /// </summary>
    public DateTime? StartTime { get; init; }

    /// <summary>
    /// 用户 ID
    /// </summary>
    public string? SubjectId { get; init; }
}
