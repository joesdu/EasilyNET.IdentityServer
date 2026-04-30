using System.Text.Json;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.EFCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.Stores;

/// <summary>
/// EF Core 持久化授权存储
/// </summary>
public class EfPersistedGrantStore(IdentityServerDbContext db) : IPersistedGrantStore
{
    public async Task StoreAsync(PersistedGrant grant, CancellationToken cancellationToken = default)
    {
        var existing = await db.PersistedGrants.FindAsync([grant.Key], cancellationToken);
        if (existing != null)
        {
            existing.Type = grant.Type;
            existing.SubjectId = grant.SubjectId;
            existing.ClientId = grant.ClientId;
            existing.SessionId = grant.SessionId;
            existing.Description = grant.Description;
            existing.CreationTime = grant.CreationTime;
            existing.ExpirationTime = grant.ExpirationTime;
            existing.ConsumedTime = grant.ConsumedTime;
            existing.Data = grant.Data;
            existing.PropertiesJson = grant.Properties.Count > 0
                ? JsonSerializer.Serialize(grant.Properties)
                : null;
        }
        else
        {
            db.PersistedGrants.Add(new()
            {
                Key = grant.Key,
                Type = grant.Type,
                SubjectId = grant.SubjectId,
                ClientId = grant.ClientId,
                SessionId = grant.SessionId,
                Description = grant.Description,
                CreationTime = grant.CreationTime,
                ExpirationTime = grant.ExpirationTime,
                ConsumedTime = grant.ConsumedTime,
                Data = grant.Data,
                PropertiesJson = grant.Properties.Count > 0
                    ? JsonSerializer.Serialize(grant.Properties)
                    : null
            });
        }
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<PersistedGrant?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        var entity = await db.PersistedGrants.FindAsync([key], cancellationToken);
        return entity == null ? null : MapToModel(entity);
    }

    public async Task<PersistedGrant?> TryConsumeAsync(string key, string expectedType, string clientId, CancellationToken cancellationToken = default)
    {
        var entity = await db.PersistedGrants.FirstOrDefaultAsync(g => g.Key == key && g.Type == expectedType && g.ClientId == clientId, cancellationToken);
        if (entity == null || entity.ConsumedTime.HasValue)
        {
            return null;
        }

        var original = MapToModel(entity);
        entity.ConsumedTime = DateTime.UtcNow;

        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return original;
        }
        catch (DbUpdateConcurrencyException)
        {
            return null;
        }
    }

    public async Task<IEnumerable<PersistedGrant>> GetAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default)
    {
        var query = db.PersistedGrants.AsQueryable();
        if (!string.IsNullOrEmpty(filter.SubjectId))
        {
            query = query.Where(g => g.SubjectId == filter.SubjectId);
        }
        if (!string.IsNullOrEmpty(filter.ClientId))
        {
            query = query.Where(g => g.ClientId == filter.ClientId);
        }
        if (!string.IsNullOrEmpty(filter.Type))
        {
            query = query.Where(g => g.Type == filter.Type);
        }
        if (!string.IsNullOrEmpty(filter.SessionId))
        {
            query = query.Where(g => g.SessionId == filter.SessionId);
        }
        var entities = await query.ToListAsync(cancellationToken);
        return entities.Select(MapToModel);
    }

    public async Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        var entity = await db.PersistedGrants.FindAsync([key], cancellationToken);
        if (entity != null)
        {
            db.PersistedGrants.Remove(entity);
            await db.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task RemoveAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default)
    {
        var query = db.PersistedGrants.AsQueryable();
        if (!string.IsNullOrEmpty(filter.SubjectId))
        {
            query = query.Where(g => g.SubjectId == filter.SubjectId);
        }
        if (!string.IsNullOrEmpty(filter.ClientId))
        {
            query = query.Where(g => g.ClientId == filter.ClientId);
        }
        if (!string.IsNullOrEmpty(filter.Type))
        {
            query = query.Where(g => g.Type == filter.Type);
        }
        var entities = await query.ToListAsync(cancellationToken);
        db.PersistedGrants.RemoveRange(entities);
        await db.SaveChangesAsync(cancellationToken);
    }

    private static PersistedGrant MapToModel(PersistedGrantEntity e) =>
        new()
        {
            Key = e.Key,
            Type = e.Type,
            SubjectId = e.SubjectId,
            ClientId = e.ClientId,
            SessionId = e.SessionId,
            Description = e.Description,
            CreationTime = e.CreationTime,
            ExpirationTime = e.ExpirationTime,
            ConsumedTime = e.ConsumedTime,
            Data = e.Data,
            Properties = string.IsNullOrEmpty(e.PropertiesJson)
                ? new Dictionary<string, string>()
                : JsonSerializer.Deserialize<Dictionary<string, string>>(e.PropertiesJson)
                  ?? new Dictionary<string, string>()
        };
}

/// <summary>
/// EF Core 设备流存储
/// </summary>
public class EfDeviceFlowStore(IdentityServerDbContext db) : IDeviceFlowStore
{
    public async Task StoreAsync(DeviceCodeData deviceCode, CancellationToken cancellationToken = default)
    {
        var entity = await db.DeviceCodes.FirstOrDefaultAsync(d => d.DeviceCode == deviceCode.Code, cancellationToken);
        var propertiesJson = deviceCode.Properties.Count > 0
            ? JsonSerializer.Serialize(deviceCode.Properties)
            : null;
        if (entity != null)
        {
            entity.UserCode = deviceCode.UserCode;
            entity.SubjectId = deviceCode.SubjectId;
            entity.ClientId = deviceCode.ClientId;
            entity.Description = deviceCode.Description;
            entity.CreationTime = deviceCode.CreationTime;
            entity.ExpirationTime = deviceCode.ExpirationTime;
            entity.Data = deviceCode.Data;
            entity.PropertiesJson = propertiesJson;
        }
        else
        {
            db.DeviceCodes.Add(new()
            {
                DeviceCode = deviceCode.Code,
                UserCode = deviceCode.UserCode,
                SubjectId = deviceCode.SubjectId,
                ClientId = deviceCode.ClientId,
                Description = deviceCode.Description,
                CreationTime = deviceCode.CreationTime,
                ExpirationTime = deviceCode.ExpirationTime,
                Data = deviceCode.Data,
                PropertiesJson = propertiesJson
            });
        }
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<DeviceCodeData?> FindByDeviceCodeAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        var entity = await db.DeviceCodes.FirstOrDefaultAsync(d => d.DeviceCode == deviceCode, cancellationToken);
        return entity == null ? null : MapToModel(entity);
    }

    public async Task<DeviceCodeData?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken = default)
    {
        var entity = await db.DeviceCodes.FirstOrDefaultAsync(d => d.UserCode == userCode, cancellationToken);
        return entity == null ? null : MapToModel(entity);
    }

    public async Task<DeviceCodeData?> TryConsumeDeviceCodeAsync(string deviceCode, string clientId, CancellationToken cancellationToken = default)
    {
        var entity = await db.DeviceCodes.FirstOrDefaultAsync(d => d.DeviceCode == deviceCode && d.ClientId == clientId, cancellationToken);
        if (entity == null || entity.Data == "consumed")
        {
            return null;
        }

        var original = MapToModel(entity);
        var affectedRows = await db.DeviceCodes
            .Where(d => d.DeviceCode == deviceCode && d.ClientId == clientId && d.Data != "consumed")
            .ExecuteUpdateAsync(setters => setters.SetProperty(d => d.Data, "consumed"), cancellationToken);

        return affectedRows == 1 ? original : null;
    }

    public async Task ConsumeDeviceCodeAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        // 标记为已消费 (通过设置 Data = "consumed" 实现，与 InMemory 存储保持一致)
        var entity = await db.DeviceCodes.FirstOrDefaultAsync(d => d.DeviceCode == deviceCode, cancellationToken);
        if (entity != null)
        {
            entity.Data = "consumed";
            await db.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task RemoveAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        var entity = await db.DeviceCodes.FirstOrDefaultAsync(d => d.DeviceCode == deviceCode, cancellationToken);
        if (entity != null)
        {
            db.DeviceCodes.Remove(entity);
            await db.SaveChangesAsync(cancellationToken);
        }
    }

    private static DeviceCodeData MapToModel(DeviceCodeEntity e) =>
        new()
        {
            Code = e.DeviceCode,
            UserCode = e.UserCode,
            SubjectId = e.SubjectId,
            ClientId = e.ClientId,
            Description = e.Description,
            CreationTime = e.CreationTime,
            ExpirationTime = e.ExpirationTime,
            Data = e.Data,
            Properties = string.IsNullOrEmpty(e.PropertiesJson)
                ? new Dictionary<string, string>()
                : JsonSerializer.Deserialize<Dictionary<string, string>>(e.PropertiesJson)
                  ?? new Dictionary<string, string>()
        };
}

/// <summary>
/// EF Core 用户 Consent 存储
/// </summary>
public class EfUserConsentStore(IdentityServerDbContext db) : IUserConsentStore
{
    public async Task StoreAsync(UserConsent consent, CancellationToken cancellationToken = default)
    {
        var existing = await db.UserConsents
                               .FirstOrDefaultAsync(c => c.SubjectId == consent.SubjectId && c.ClientId == consent.ClientId, cancellationToken);
        if (existing != null)
        {
            existing.Scopes = string.Join(" ", consent.Scopes);
            existing.CreationTime = consent.CreationTime;
            existing.ExpirationTime = consent.ExpirationTime;
        }
        else
        {
            db.UserConsents.Add(new()
            {
                SubjectId = consent.SubjectId,
                ClientId = consent.ClientId,
                Scopes = string.Join(" ", consent.Scopes),
                CreationTime = consent.CreationTime,
                ExpirationTime = consent.ExpirationTime
            });
        }
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<UserConsent?> GetAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        var entity = await db.UserConsents
                             .FirstOrDefaultAsync(c => c.SubjectId == subjectId && c.ClientId == clientId, cancellationToken);
        return entity == null
                   ? null
                   : new UserConsent
                   {
                       SubjectId = entity.SubjectId,
                       ClientId = entity.ClientId,
                       Scopes = entity.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries),
                       CreationTime = entity.CreationTime,
                       ExpirationTime = entity.ExpirationTime
                   };
    }

    public async Task RemoveAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        var entity = await db.UserConsents
                             .FirstOrDefaultAsync(c => c.SubjectId == subjectId && c.ClientId == clientId, cancellationToken);
        if (entity != null)
        {
            db.UserConsents.Remove(entity);
            await db.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task RemoveAllAsync(string subjectId, CancellationToken cancellationToken = default)
    {
        var entities = await db.UserConsents.Where(c => c.SubjectId == subjectId).ToListAsync(cancellationToken);
        db.UserConsents.RemoveRange(entities);
        await db.SaveChangesAsync(cancellationToken);
    }
}
