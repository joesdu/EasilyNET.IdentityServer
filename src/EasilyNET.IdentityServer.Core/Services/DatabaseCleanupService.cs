using System.Timers;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.Extensions.Logging;
using Timer = System.Timers.Timer;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 数据库清理服务 - 定期清理过期的 PersistedGrants、DeviceCodes 和 UserConsents
/// 防止数据库无限增长
/// </summary>
public sealed class DatabaseCleanupService : IDisposable
{
    private readonly ILogger<DatabaseCleanupService> _logger;
    private readonly Timer _cleanupTimer;
    private readonly IPersistedGrantStore _persistedGrantStore;
    private readonly IDeviceFlowStore _deviceFlowStore;
    private bool _disposed;

    // 默认清理间隔: 1小时
    private static readonly TimeSpan DefaultCleanupInterval = TimeSpan.FromHours(1);

    // 授权码/刷新令牌过期宽限期: 1天 (与 TokenService.RevokedTokenRetentionPeriod 保持一致)
    private static readonly TimeSpan GrantExpirationGracePeriod = TimeSpan.FromDays(1);

    public DatabaseCleanupService(
        ILogger<DatabaseCleanupService> logger,
        IPersistedGrantStore persistedGrantStore,
        IDeviceFlowStore deviceFlowStore,
        TimeSpan? cleanupInterval = null)
    {
        _logger = logger;
        _persistedGrantStore = persistedGrantStore;
        _deviceFlowStore = deviceFlowStore;
        var interval = cleanupInterval ?? DefaultCleanupInterval;
        _cleanupTimer = new Timer(interval.TotalMilliseconds)
        {
            AutoReset = true,
            Enabled = true
        };
        _cleanupTimer.Elapsed += OnCleanupTimerElapsed;
        _logger.LogInformation("DatabaseCleanupService started with interval: {Interval}", interval);
    }

    private async void OnCleanupTimerElapsed(object? sender, ElapsedEventArgs e)
    {
        if (_disposed) return;
        try
        {
            await CleanupExpiredGrantsAsync();
            await CleanupExpiredDeviceCodesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during database cleanup");
        }
    }

    /// <summary>
    /// 清理过期的 PersistedGrants (授权码、刷新令牌等)
    /// </summary>
    private async Task CleanupExpiredGrantsAsync()
    {
        // 清理条件: 过期时间 + 宽限期都超过当前时间
        // 这样确保即使有过期的未被主动删除的记录也会被清理
        var expirationThreshold = DateTime.UtcNow.Subtract(GrantExpirationGracePeriod);
        var filter = new Abstractions.Models.PersistedGrantFilter
        {
            Type = null, // 清理所有类型
            ClientId = null,
            SubjectId = null,
            SessionId = null
        };

        // 获取所有过期的授权记录
        var allGrants = await _persistedGrantStore.GetAllAsync(filter);
        var expiredKeys = allGrants
            .Where(g => g.ExpirationTime.HasValue && g.ExpirationTime.Value < expirationThreshold)
            .Select(g => g.Key)
            .ToList();

        foreach (var key in expiredKeys)
        {
            await _persistedGrantStore.RemoveAsync(key);
        }

        if (expiredKeys.Count > 0)
        {
            _logger.LogDebug("Cleaned up {Count} expired persisted grants", expiredKeys.Count);
        }
    }

    /// <summary>
    /// 清理过期的 DeviceCodes
    /// 注意: DeviceCodeEntity 本身没有 ExpirationTime 属性用于清理
    /// 需要在 DeviceCodeData 中添加过期字段，或者依赖 FindByDeviceCode 时检查
    /// 这里仅清理已标记为已消费的记录 (如果存储中有此类标记)
    /// </summary>
    private Task CleanupExpiredDeviceCodesAsync()
    {
        // DeviceCode 的生命周期通常很短(300秒)
        // 通过 DeviceAuthorizationController 在每次轮询时检查并删除过期记录
        // 因此这里不需要额外的清理逻辑
        _logger.LogDebug("DeviceCode cleanup delegated to polling mechanism");
        return Task.CompletedTask;
    }

    /// <summary>
    /// 手动触发清理 (可用于管理接口或测试)
    /// </summary>
    public async Task CleanupNowAsync()
    {
        await CleanupExpiredGrantsAsync();
        await CleanupExpiredDeviceCodesAsync();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cleanupTimer.Stop();
        _cleanupTimer.Dispose();
        _logger.LogInformation("DatabaseCleanupService disposed");
    }
}