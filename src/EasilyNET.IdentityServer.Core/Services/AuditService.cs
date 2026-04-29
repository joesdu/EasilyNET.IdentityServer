using System.Collections.Concurrent;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 审计服务实现
/// </summary>
public class AuditService : IAuditService
{
    private readonly IAuditLogStore _auditLogStore;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuditService> _logger;

    public AuditService(
        IAuditLogStore auditLogStore,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuditService> logger)
    {
        _auditLogStore = auditLogStore;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task LogEventAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        try
        {
            await _auditLogStore.StoreAsync(auditEvent, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write audit log for event {EventType}", auditEvent.EventType);
        }
    }

    /// <inheritdoc />
    public Task LogTokenIssuedAsync(string clientId, string? subjectId, string grantType, IEnumerable<string> scopes, string? ipAddress, CancellationToken cancellationToken = default)
    {
        return LogEventAsync(new AuditEvent
        {
            EventType = AuditEventTypes.TokenIssued,
            ClientId = clientId,
            SubjectId = subjectId,
            GrantType = grantType,
            Scopes = scopes,
            Success = true,
            IpAddress = ipAddress ?? GetClientIpAddress(),
            UserAgent = GetUserAgent(),
            RequestPath = GetRequestPath()
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task LogTokenRevokedAsync(string clientId, string tokenType, string? ipAddress, CancellationToken cancellationToken = default)
    {
        return LogEventAsync(new AuditEvent
        {
            EventType = AuditEventTypes.TokenRevoked,
            ClientId = clientId,
            Success = true,
            IpAddress = ipAddress ?? GetClientIpAddress(),
            UserAgent = GetUserAgent(),
            RequestPath = GetRequestPath(),
            Properties = new Dictionary<string, string> { ["token_type"] = tokenType }
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task LogAuthenticationFailedAsync(string clientId, string grantType, string reason, string? ipAddress, CancellationToken cancellationToken = default)
    {
        return LogEventAsync(new AuditEvent
        {
            EventType = AuditEventTypes.AuthenticationFailed,
            ClientId = clientId,
            GrantType = grantType,
            Success = false,
            FailureReason = reason,
            IpAddress = ipAddress ?? GetClientIpAddress(),
            UserAgent = GetUserAgent(),
            RequestPath = GetRequestPath()
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task LogAuthorizationCodeExchangedAsync(string clientId, string? subjectId, string? ipAddress, CancellationToken cancellationToken = default)
    {
        return LogEventAsync(new AuditEvent
        {
            EventType = AuditEventTypes.AuthorizationCodeExchanged,
            ClientId = clientId,
            SubjectId = subjectId,
            GrantType = GrantType.AuthorizationCode,
            Success = true,
            IpAddress = ipAddress ?? GetClientIpAddress(),
            UserAgent = GetUserAgent(),
            RequestPath = GetRequestPath()
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task LogRefreshTokenUsedAsync(string clientId, string? subjectId, bool rotated, string? ipAddress, CancellationToken cancellationToken = default)
    {
        return LogEventAsync(new AuditEvent
        {
            EventType = AuditEventTypes.RefreshTokenUsed,
            ClientId = clientId,
            SubjectId = subjectId,
            GrantType = GrantType.RefreshToken,
            Success = true,
            IpAddress = ipAddress ?? GetClientIpAddress(),
            UserAgent = GetUserAgent(),
            RequestPath = GetRequestPath(),
            Properties = new Dictionary<string, string> { ["rotated"] = rotated.ToString() }
        }, cancellationToken);
    }

    private string? GetClientIpAddress()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null) return null;

        // 优先从 X-Forwarded-For 获取（代理场景）
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }

        return context.Connection.RemoteIpAddress?.ToString();
    }

    private string? GetUserAgent()
    {
        return _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"].FirstOrDefault();
    }

    private string? GetRequestPath()
    {
        return _httpContextAccessor.HttpContext?.Request.Path;
    }
}

/// <summary>
/// 内存审计日志存储（开发环境使用）
/// </summary>
public class InMemoryAuditLogStore : IAuditLogStore
{
    private readonly ConcurrentBag<AuditEvent> _logs = new();

    public Task StoreAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        _logs.Add(auditEvent);
        return Task.CompletedTask;
    }

    public Task<IEnumerable<AuditEvent>> QueryAsync(AuditLogFilter filter, CancellationToken cancellationToken = default)
    {
        var query = _logs.AsEnumerable();

        if (!string.IsNullOrEmpty(filter.EventType))
            query = query.Where(e => e.EventType == filter.EventType);

        if (!string.IsNullOrEmpty(filter.ClientId))
            query = query.Where(e => e.ClientId == filter.ClientId);

        if (!string.IsNullOrEmpty(filter.SubjectId))
            query = query.Where(e => e.SubjectId == filter.SubjectId);

        if (filter.StartTime.HasValue)
            query = query.Where(e => e.Timestamp >= filter.StartTime.Value);

        if (filter.EndTime.HasValue)
            query = query.Where(e => e.Timestamp <= filter.EndTime.Value);

        if (filter.Success.HasValue)
            query = query.Where(e => e.Success == filter.Success.Value);

        query = query.OrderByDescending(e => e.Timestamp);

        if (filter.Limit.HasValue)
            query = query.Take(filter.Limit.Value);

        return Task.FromResult(query);
    }

    public Task PurgeOldLogsAsync(DateTime cutoff, CancellationToken cancellationToken = default)
    {
        // 内存存储不需要清理，重启后自动清空
        return Task.CompletedTask;
    }
}
