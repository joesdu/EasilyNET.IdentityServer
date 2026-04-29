using System.Collections.Concurrent;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 内存速率限制服务实现（使用滑动窗口算法）
/// </summary>
public class RateLimitService : IRateLimitService, IDisposable
{
    private readonly RateLimitOptions _options;
    private readonly ILogger<RateLimitService> _logger;
    private readonly ConcurrentDictionary<string, RateLimitEntry> _entries = new();
    private readonly Timer _cleanupTimer;
    private readonly Lock _lock = new();

    public RateLimitService(
        IOptions<RateLimitOptions> options,
        ILogger<RateLimitService> logger)
    {
        _options = options.Value;
        _logger = logger;

        // 启动清理定时器
        var cleanupInterval = TimeSpan.FromMinutes(_options.CleanupIntervalMinutes);
        _cleanupTimer = new Timer(CleanupExpiredEntries, null, cleanupInterval, cleanupInterval);
    }

    public Task<bool> IsAllowedAsync(string key, RateLimitType limitType, CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
            return Task.FromResult(true);

        var entryKey = GetEntryKey(key, limitType);
        var now = DateTimeOffset.UtcNow;

        // 获取对应的规则
        var rule = GetRuleForLimitType(limitType);

        var entry = _entries.GetOrAdd(entryKey, _ => new RateLimitEntry
        {
            WindowStart = now,
            Requests = new ConcurrentQueue<DateTimeOffset>()
        });

        lock (entry.Lock)
        {
            // 清理过期请求
            CleanupExpiredRequests(entry, now, rule.WindowSeconds);

            // 检查是否超过限制
            var isAllowed = entry.Requests.Count < rule.MaxRequests;

            if (!isAllowed)
            {
                _logger.LogWarning("Rate limit exceeded for key: {Key}, type: {LimitType}, count: {Count}",
                    key, limitType, entry.Requests.Count);
            }

            return Task.FromResult(isAllowed);
        }
    }

    public Task RecordRequestAsync(string key, RateLimitType limitType, CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
            return Task.CompletedTask;

        var entryKey = GetEntryKey(key, limitType);
        var now = DateTimeOffset.UtcNow;

        var entry = _entries.GetOrAdd(entryKey, _ => new RateLimitEntry
        {
            WindowStart = now,
            Requests = new ConcurrentQueue<DateTimeOffset>()
        });

        lock (entry.Lock)
        {
            entry.Requests.Enqueue(now);
        }

        return Task.CompletedTask;
    }

    public Task<int> GetRemainingRequestsAsync(string key, RateLimitType limitType, CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
            return Task.FromResult(int.MaxValue);

        var entryKey = GetEntryKey(key, limitType);
        var now = DateTimeOffset.UtcNow;

        var rule = GetRuleForLimitType(limitType);

        if (!_entries.TryGetValue(entryKey, out var entry))
        {
            return Task.FromResult(rule.MaxRequests);
        }

        lock (entry.Lock)
        {
            CleanupExpiredRequests(entry, now, rule.WindowSeconds);
            return Task.FromResult(Math.Max(0, rule.MaxRequests - entry.Requests.Count));
        }
    }

    public Task<DateTimeOffset> GetResetTimeAsync(string key, RateLimitType limitType, CancellationToken cancellationToken = default)
    {
        var entryKey = GetEntryKey(key, limitType);
        var rule = GetRuleForLimitType(limitType);

        if (!_entries.TryGetValue(entryKey, out var entry) || entry.Requests.IsEmpty)
        {
            return Task.FromResult(DateTimeOffset.UtcNow);
        }

        lock (entry.Lock)
        {
            // 找到最早的请求，重置时间为该请求时间 + 窗口时间
            if (entry.Requests.TryPeek(out var oldestRequest))
            {
                return Task.FromResult(oldestRequest.AddSeconds(rule.WindowSeconds));
            }

            return Task.FromResult(DateTimeOffset.UtcNow);
        }
    }

    public Task ClearLimitAsync(string key, CancellationToken cancellationToken = default)
    {
        var keysToRemove = _entries.Keys
            .Where(k => k.StartsWith(key + ":", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var entryKey in keysToRemove)
        {
            _entries.TryRemove(entryKey, out _);
        }

        _logger.LogInformation("Cleared rate limits for key: {Key}, removed {Count} entries", key, keysToRemove.Count);

        return Task.CompletedTask;
    }

    /// <summary>
    /// 检查 IP 是否在白名单中
    /// </summary>
    public bool IsIpWhitelisted(string ip)
    {
        return _options.WhitelistIps.Contains(ip, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 检查客户端是否在白名单中
    /// </summary>
    public bool IsClientWhitelisted(string clientId)
    {
        return _options.WhitelistClients.Contains(clientId, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 根据端点路径获取速率限制类型
    /// </summary>
    public RateLimitType GetLimitTypeForEndpoint(string path)
    {
        if (path.Contains("/connect/token", StringComparison.OrdinalIgnoreCase))
            return RateLimitType.TokenEndpoint;
        if (path.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase))
            return RateLimitType.AuthorizeEndpoint;
        if (path.Contains("/connect/device_authorization", StringComparison.OrdinalIgnoreCase))
            return RateLimitType.DeviceAuthorizationEndpoint;
        if (path.Contains("/connect/device_verify", StringComparison.OrdinalIgnoreCase))
            return RateLimitType.VerifyEndpoint;

        return RateLimitType.General;
    }

    private void CleanupExpiredRequests(RateLimitEntry entry, DateTimeOffset now, int windowSeconds)
    {
        var cutoff = now.AddSeconds(-windowSeconds);

        while (entry.Requests.TryPeek(out var timestamp) && timestamp < cutoff)
        {
            entry.Requests.TryDequeue(out _);
        }
    }

    private void CleanupExpiredEntries(object? state)
    {
        try
        {
            var now = DateTimeOffset.UtcNow;
            var keysToRemove = new List<string>();

            foreach (var kvp in _entries)
            {
                var limitType = Enum.Parse<RateLimitType>(kvp.Key.Split(':').Last());
                var rule = GetRuleForLimitType(limitType);
                var cutoff = now.AddSeconds(-rule.WindowSeconds * 2); // 2倍窗口时间后清理

                lock (kvp.Value.Lock)
                {
                    if (kvp.Value.WindowStart < cutoff && kvp.Value.Requests.IsEmpty)
                    {
                        keysToRemove.Add(kvp.Key);
                    }
                }
            }

            foreach (var key in keysToRemove)
            {
                _entries.TryRemove(key, out _);
            }

            if (keysToRemove.Count > 0)
            {
                _logger.LogDebug("Cleaned up {Count} expired rate limit entries", keysToRemove.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during rate limit cleanup");
        }
    }

    private static string GetEntryKey(string key, RateLimitType limitType)
    {
        return $"{key}:{limitType}";
    }

    private RateLimitRuleConfig GetRuleForLimitType(RateLimitType limitType)
    {
        var path = limitType switch
        {
            RateLimitType.TokenEndpoint => "/connect/token",
            RateLimitType.AuthorizeEndpoint => "/connect/authorize",
            RateLimitType.DeviceAuthorizationEndpoint => "/connect/device_authorization",
            RateLimitType.VerifyEndpoint => "/connect/device_verify",
            _ => "*"
        };

        return _options.IpLimits.FirstOrDefault(r =>
            r.EndpointPattern.Equals(path, StringComparison.OrdinalIgnoreCase)) ??
            _options.IpLimits.First(r => r.EndpointPattern == "*");
    }

    public void Dispose()
    {
        _cleanupTimer?.Dispose();
    }
}

/// <summary>
/// 速率限制条目
/// </summary>
internal class RateLimitEntry
{
    public DateTimeOffset WindowStart { get; set; }
    public ConcurrentQueue<DateTimeOffset> Requests { get; set; } = new();
    public Lock Lock { get; } = new();
}
