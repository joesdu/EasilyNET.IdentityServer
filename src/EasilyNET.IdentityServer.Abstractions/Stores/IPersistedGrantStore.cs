using EasilyNET.IdentityServer.Abstractions.Models;

namespace EasilyNET.IdentityServer.Abstractions.Stores;

/// <summary>
/// 持久化授权存储接口
/// </summary>
public interface IPersistedGrantStore
{
    /// <summary>
    /// 存储授权
    /// </summary>
    Task StoreAsync(PersistedGrant grant, CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取授权
    /// </summary>
    Task<PersistedGrant?> GetAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// 尝试以原子方式消费授权/令牌，仅当记录尚未消费时成功。
    /// </summary>
    Task<PersistedGrant?> TryConsumeAsync(string key, string expectedType, string clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取所有匹配的授权
    /// </summary>
    Task<IEnumerable<PersistedGrant>> GetAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default);

    /// <summary>
    /// 移除授权
    /// </summary>
    Task RemoveAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// 批量移除在指定时间之前过期的授权，返回删除数量。
    /// </summary>
    Task<int> RemoveExpiredAsync(DateTime cutoff, CancellationToken cancellationToken = default);

    /// <summary>
    /// 移除所有匹配的授权
    /// </summary>
    Task RemoveAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default);
}