using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 数据库清理服务 - 定期清理过期的 PersistedGrants、DeviceCodes 和 UserConsents
/// 防止数据库无限增长
/// </summary>
public sealed class DatabaseCleanupService : BackgroundService
{
    private readonly ILogger<DatabaseCleanupService> _logger;
    private readonly IPersistedGrantStore _persistedGrantStore;
    private readonly IDeviceFlowStore _deviceFlowStore;
    private readonly TimeSpan _cleanupInterval;

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
        _cleanupInterval = cleanupInterval ?? DefaultCleanupInterval;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("DatabaseCleanupService started with interval: {Interval}", _cleanupInterval);
        await RunCleanupCycleAsync(stoppingToken);

        using var timer = new PeriodicTimer(_cleanupInterval);

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await RunCleanupCycleAsync(stoppingToken);
        }

        _logger.LogInformation("DatabaseCleanupService stopped");
    }

    private async Task RunCleanupCycleAsync(CancellationToken cancellationToken)
    {
        try
        {
            await CleanupNowAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during database cleanup");
        }
    }

    /// <summary>
    /// 清理过期的 PersistedGrants (授权码、刷新令牌等)
    /// </summary>
    private async Task CleanupExpiredGrantsAsync(CancellationToken cancellationToken)
    {
        // 清理条件: 过期时间 + 宽限期都超过当前时间
        // 这样确保即使有过期的未被主动删除的记录也会被清理
        var expirationThreshold = DateTime.UtcNow.Subtract(GrantExpirationGracePeriod);
        var removedCount = await _persistedGrantStore.RemoveExpiredAsync(expirationThreshold, cancellationToken);

        if (removedCount > 0)
        {
            _logger.LogDebug("Cleaned up {Count} expired persisted grants", removedCount);
        }
    }

    /// <summary>
    /// 清理过期的 DeviceCodes
    /// 注意: DeviceCodeEntity 本身没有 ExpirationTime 属性用于清理
    /// 需要在 DeviceCodeData 中添加过期字段，或者依赖 FindByDeviceCode 时检查
    /// 这里仅清理已标记为已消费的记录 (如果存储中有此类标记)
    /// </summary>
    private async Task CleanupExpiredDeviceCodesAsync(CancellationToken cancellationToken)
    {
        var removedCount = await _deviceFlowStore.RemoveExpiredAsync(DateTime.UtcNow, cancellationToken);
        if (removedCount > 0)
        {
            _logger.LogDebug("Cleaned up {Count} expired device codes", removedCount);
        }
    }

    /// <summary>
    /// 手动触发清理 (可用于管理接口或测试)
    /// </summary>
    public async Task CleanupNowAsync(CancellationToken cancellationToken = default)
    {
        await CleanupExpiredGrantsAsync(cancellationToken);
        await CleanupExpiredDeviceCodesAsync(cancellationToken);
    }
}