using System.Text.Json;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.EFCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.Stores;

/// <summary>
/// EF Core 审计日志存储
/// </summary>
public sealed class EfAuditLogStore(IdentityServerDbContext db) : IAuditLogStore
{
    public async Task StoreAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        db.AuditLogs.Add(new AuditLogEntity
        {
            EventType = auditEvent.EventType,
            Timestamp = auditEvent.Timestamp,
            ClientId = auditEvent.ClientId,
            SubjectId = auditEvent.SubjectId,
            GrantType = auditEvent.GrantType,
            Scopes = auditEvent.Scopes == null ? null : string.Join(" ", auditEvent.Scopes),
            Success = auditEvent.Success,
            FailureReason = auditEvent.FailureReason,
            IpAddress = auditEvent.IpAddress,
            UserAgent = auditEvent.UserAgent,
            RequestPath = auditEvent.RequestPath,
            PropertiesJson = auditEvent.Properties == null || auditEvent.Properties.Count == 0
                ? null
                : JsonSerializer.Serialize(auditEvent.Properties)
        });

        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<IEnumerable<AuditEvent>> QueryAsync(AuditLogFilter filter, CancellationToken cancellationToken = default)
    {
        var query = db.AuditLogs.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(filter.EventType))
        {
            query = query.Where(x => x.EventType == filter.EventType);
        }

        if (!string.IsNullOrWhiteSpace(filter.ClientId))
        {
            query = query.Where(x => x.ClientId == filter.ClientId);
        }

        if (!string.IsNullOrWhiteSpace(filter.SubjectId))
        {
            query = query.Where(x => x.SubjectId == filter.SubjectId);
        }

        if (filter.StartTime.HasValue)
        {
            query = query.Where(x => x.Timestamp >= filter.StartTime.Value);
        }

        if (filter.EndTime.HasValue)
        {
            query = query.Where(x => x.Timestamp <= filter.EndTime.Value);
        }

        if (filter.Success.HasValue)
        {
            query = query.Where(x => x.Success == filter.Success.Value);
        }

        query = query.OrderByDescending(x => x.Timestamp);

        if (filter.Limit is > 0)
        {
            query = query.Take(filter.Limit.Value);
        }

        var entities = await query.ToListAsync(cancellationToken);
        return entities.Select(MapToModel);
    }

    public Task PurgeOldLogsAsync(DateTime cutoff, CancellationToken cancellationToken = default)
    {
        return db.AuditLogs
                 .Where(x => x.Timestamp < cutoff)
                 .ExecuteDeleteAsync(cancellationToken);
    }

    private static AuditEvent MapToModel(AuditLogEntity entity)
    {
        return new AuditEvent
        {
            EventType = entity.EventType,
            Timestamp = entity.Timestamp,
            ClientId = entity.ClientId,
            SubjectId = entity.SubjectId,
            GrantType = entity.GrantType,
            Scopes = string.IsNullOrWhiteSpace(entity.Scopes)
                ? null
                : entity.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            Success = entity.Success,
            FailureReason = entity.FailureReason,
            IpAddress = entity.IpAddress,
            UserAgent = entity.UserAgent,
            RequestPath = entity.RequestPath,
            Properties = string.IsNullOrWhiteSpace(entity.PropertiesJson)
                ? null
                : JsonSerializer.Deserialize<Dictionary<string, string>>(entity.PropertiesJson)
        };
    }
}