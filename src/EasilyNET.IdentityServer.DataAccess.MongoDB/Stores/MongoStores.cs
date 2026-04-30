using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using MongoDB.Driver;

namespace EasilyNET.IdentityServer.DataAccess.MongoDB.Stores;

/// <summary>
/// MongoDB 客户端存储
/// </summary>
public class MongoClientStore(IMongoDatabase database) : IClientStore
{
    private IMongoCollection<Client> Collection => database.GetCollection<Client>("clients");

    public Task CreateClientAsync(Client client, CancellationToken cancellationToken = default)
    {
        return Collection.InsertOneAsync(client, cancellationToken: cancellationToken);
    }

    public async Task<Client?> FindClientByIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(c => c.ClientId == clientId).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<IEnumerable<Client>> FindEnabledClientsAsync(CancellationToken cancellationToken = default)
    {
        return await Collection.Find(c => c.Enabled).ToListAsync(cancellationToken);
    }
}

/// <summary>
/// MongoDB 资源存储
/// </summary>
public class MongoResourceStore(IMongoDatabase database) : IResourceStore
{
    private IMongoCollection<ApiResource> ApiResources => database.GetCollection<ApiResource>("apiResources");

    private IMongoCollection<ApiScope> ApiScopes => database.GetCollection<ApiScope>("apiScopes");

    private IMongoCollection<IdentityResource> IdentityResources => database.GetCollection<IdentityResource>("identityResources");

    public async Task<IEnumerable<ApiResource>> FindEnabledApiResourcesAsync(CancellationToken cancellationToken = default)
    {
        return await ApiResources.Find(r => r.Enabled).ToListAsync(cancellationToken);
    }

    public async Task<IEnumerable<IdentityResource>> FindEnabledIdentityResourcesAsync(CancellationToken cancellationToken = default)
    {
        return await IdentityResources.Find(r => r.Enabled).ToListAsync(cancellationToken);
    }

    public async Task<IEnumerable<ApiResource>> FindApiResourcesByScopeAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default)
    {
        var names = scopeNames.ToHashSet();
        var filter = Builders<ApiResource>.Filter.Where(r => r.Enabled && r.Scopes.Any(s => names.Contains(s)));
        return await ApiResources.Find(filter).ToListAsync(cancellationToken);
    }

    public async Task<IEnumerable<ApiScope>> FindEnabledScopesAsync(CancellationToken cancellationToken = default)
    {
        return await ApiScopes.Find(s => s.Enabled).ToListAsync(cancellationToken);
    }

    public async Task<IEnumerable<ApiScope>> FindScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default)
    {
        var names = scopeNames.ToHashSet();
        var filter = Builders<ApiScope>.Filter.Where(s => s.Enabled && names.Contains(s.Name));
        return await ApiScopes.Find(filter).ToListAsync(cancellationToken);
    }

    public async Task<Resources> GetAllResourcesAsync(CancellationToken cancellationToken = default) =>
        new()
        {
            ApiResources = (await FindEnabledApiResourcesAsync(cancellationToken)).ToList(),
            ApiScopes = (await FindEnabledScopesAsync(cancellationToken)).ToList(),
            IdentityResources = (await FindEnabledIdentityResourcesAsync(cancellationToken)).ToList()
        };
}

/// <summary>
/// MongoDB 持久化授权存储
/// </summary>
public class MongoPersistedGrantStore(IMongoDatabase database) : IPersistedGrantStore
{
    private IMongoCollection<PersistedGrant> Collection => database.GetCollection<PersistedGrant>("persistedGrants");

    public async Task StoreAsync(PersistedGrant grant, CancellationToken cancellationToken = default)
    {
        var filter = Builders<PersistedGrant>.Filter.Eq(g => g.Key, grant.Key);
        await Collection.ReplaceOneAsync(filter, grant, new ReplaceOptions { IsUpsert = true }, cancellationToken);
    }

    public async Task<PersistedGrant?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        var entity = await Collection.Find(g => g.Key == key).FirstOrDefaultAsync(cancellationToken);
        return entity;
    }

    public async Task<PersistedGrant?> TryConsumeAsync(string key, string expectedType, string clientId, CancellationToken cancellationToken = default)
    {
        var filter = Builders<PersistedGrant>.Filter.Eq(g => g.Key, key) &
                     Builders<PersistedGrant>.Filter.Eq(g => g.Type, expectedType) &
                     Builders<PersistedGrant>.Filter.Eq(g => g.ClientId, clientId) &
                     Builders<PersistedGrant>.Filter.Eq(g => g.ConsumedTime, null as DateTime?);
        var update = Builders<PersistedGrant>.Update.Set(g => g.ConsumedTime, DateTime.UtcNow);

        return await Collection.FindOneAndUpdateAsync(
            filter,
            update,
            new FindOneAndUpdateOptions<PersistedGrant> { ReturnDocument = ReturnDocument.Before },
            cancellationToken);
    }

    public async Task<IEnumerable<PersistedGrant>> GetAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default)
    {
        var builder = Builders<PersistedGrant>.Filter;
        var filters = new List<FilterDefinition<PersistedGrant>>();
        if (!string.IsNullOrEmpty(filter.SubjectId))
        {
            filters.Add(builder.Eq(g => g.SubjectId, filter.SubjectId));
        }
        if (!string.IsNullOrEmpty(filter.ClientId))
        {
            filters.Add(builder.Eq(g => g.ClientId, filter.ClientId));
        }
        if (!string.IsNullOrEmpty(filter.Type))
        {
            filters.Add(builder.Eq(g => g.Type, filter.Type));
        }
        if (!string.IsNullOrEmpty(filter.SessionId))
        {
            filters.Add(builder.Eq(g => g.SessionId, filter.SessionId));
        }
        var combined = filters.Count > 0 ? builder.And(filters) : builder.Empty;
        return await Collection.Find(combined).ToListAsync(cancellationToken);
    }

    public async Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        await Collection.DeleteOneAsync(g => g.Key == key, cancellationToken);
    }

    public async Task<int> RemoveExpiredAsync(DateTime cutoff, CancellationToken cancellationToken = default)
    {
        var result = await Collection.DeleteManyAsync(g => g.ExpirationTime != null && g.ExpirationTime < cutoff, cancellationToken);
        return (int)result.DeletedCount;
    }

    public async Task RemoveAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default)
    {
        var builder = Builders<PersistedGrant>.Filter;
        var filters = new List<FilterDefinition<PersistedGrant>>();
        if (!string.IsNullOrEmpty(filter.SubjectId))
        {
            filters.Add(builder.Eq(g => g.SubjectId, filter.SubjectId));
        }
        if (!string.IsNullOrEmpty(filter.ClientId))
        {
            filters.Add(builder.Eq(g => g.ClientId, filter.ClientId));
        }
        if (!string.IsNullOrEmpty(filter.Type))
        {
            filters.Add(builder.Eq(g => g.Type, filter.Type));
        }
        if (!string.IsNullOrEmpty(filter.SessionId))
        {
            filters.Add(builder.Eq(g => g.SessionId, filter.SessionId));
        }
        var combined = filters.Count > 0 ? builder.And(filters) : builder.Empty;
        await Collection.DeleteManyAsync(combined, cancellationToken);
    }
}

/// <summary>
/// MongoDB 设备流存储
/// </summary>
public class MongoDeviceFlowStore(IMongoDatabase database) : IDeviceFlowStore
{
    private IMongoCollection<DeviceCodeData> Collection => database.GetCollection<DeviceCodeData>("deviceCodes");

    public async Task StoreAsync(DeviceCodeData deviceCode, CancellationToken cancellationToken = default)
    {
        var filter = Builders<DeviceCodeData>.Filter.Eq(d => d.Code, deviceCode.Code);
        await Collection.ReplaceOneAsync(filter, deviceCode, new ReplaceOptions { IsUpsert = true }, cancellationToken);
    }

    public async Task<DeviceCodeData?> FindByDeviceCodeAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(d => d.Code == deviceCode).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<DeviceCodeData?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(d => d.UserCode == userCode).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<DeviceCodeData?> TryConsumeDeviceCodeAsync(string deviceCode, string clientId, CancellationToken cancellationToken = default)
    {
        var filter = Builders<DeviceCodeData>.Filter.Eq(d => d.Code, deviceCode) &
                     Builders<DeviceCodeData>.Filter.Eq(d => d.ClientId, clientId) &
                     Builders<DeviceCodeData>.Filter.Ne(d => d.Data, "consumed");
        var update = Builders<DeviceCodeData>.Update.Set(d => d.Data, "consumed");

        return await Collection.FindOneAndUpdateAsync(
            filter,
            update,
            new FindOneAndUpdateOptions<DeviceCodeData> { ReturnDocument = ReturnDocument.Before },
            cancellationToken);
    }

    public async Task ConsumeDeviceCodeAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        // 标记为已消费，通过设置 Data = "consumed" 实现，与其他存储保持一致
        var filter = Builders<DeviceCodeData>.Filter.Eq(d => d.Code, deviceCode);
        var update = Builders<DeviceCodeData>.Update.Set(d => d.Data, "consumed");
        await Collection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken);
    }

    public async Task RemoveAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        await Collection.DeleteOneAsync(d => d.Code == deviceCode, cancellationToken);
    }

    public async Task<int> RemoveExpiredAsync(DateTime cutoff, CancellationToken cancellationToken = default)
    {
        var result = await Collection.DeleteManyAsync(d => d.ExpirationTime < cutoff, cancellationToken);
        return (int)result.DeletedCount;
    }
}

/// <summary>
/// MongoDB 用户 Consent 存储
/// </summary>
public class MongoUserConsentStore(IMongoDatabase database) : IUserConsentStore
{
    private IMongoCollection<UserConsent> Collection => database.GetCollection<UserConsent>("userConsents");

    public async Task StoreAsync(UserConsent consent, CancellationToken cancellationToken = default)
    {
        var filter = Builders<UserConsent>.Filter.Where(c => c.SubjectId == consent.SubjectId && c.ClientId == consent.ClientId);
        // 统一使用原始对象存储，让 MongoDB 驱动处理 IEnumerable<string> 的序列化
        await Collection.ReplaceOneAsync(filter, consent, new ReplaceOptions { IsUpsert = true }, cancellationToken);
    }

    public async Task<UserConsent?> GetAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(c => c.SubjectId == subjectId && c.ClientId == clientId).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task RemoveAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        await Collection.DeleteOneAsync(c => c.SubjectId == subjectId && c.ClientId == clientId, cancellationToken);
    }

    public async Task RemoveAllAsync(string subjectId, CancellationToken cancellationToken = default)
    {
        await Collection.DeleteManyAsync(c => c.SubjectId == subjectId, cancellationToken);
    }
}

/// <summary>
/// MongoDB 签名密钥存储
/// </summary>
public class MongoSigningKeyStore(IMongoDatabase database) : ISigningKeyStore
{
    private IMongoCollection<SigningKey> Collection => database.GetCollection<SigningKey>("signingKeys");

    public async Task<IEnumerable<SigningKey>> GetAllKeysAsync(CancellationToken cancellationToken = default)
    {
        return await Collection.Find(Builders<SigningKey>.Filter.Empty)
                               .SortByDescending(k => k.CreatedAt)
                               .ToListAsync(cancellationToken);
    }

    public async Task<SigningKey?> GetActiveKeyAsync(CancellationToken cancellationToken = default)
    {
        return await Collection.Find(k => k.DisabledAt == null)
                               .SortByDescending(k => k.CreatedAt)
                               .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task StoreKeyAsync(SigningKey key, CancellationToken cancellationToken = default)
    {
        var filter = Builders<SigningKey>.Filter.Eq(k => k.KeyId, key.KeyId);
        await Collection.ReplaceOneAsync(filter, key, new ReplaceOptions { IsUpsert = true }, cancellationToken);
    }

    public async Task DisableKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        var filter = Builders<SigningKey>.Filter.Eq(k => k.KeyId, keyId);
        var update = Builders<SigningKey>.Update.Set(k => k.DisabledAt, DateTime.UtcNow);
        await Collection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken);
    }

    public async Task RemoveExpiredKeysAsync(DateTime cutoff, CancellationToken cancellationToken = default)
    {
        await Collection.DeleteManyAsync(k => k.DisabledAt != null && k.DisabledAt < cutoff, cancellationToken);
    }
}

/// <summary>
/// MongoDB 审计日志存储
/// </summary>
public class MongoAuditLogStore(IMongoDatabase database) : IAuditLogStore
{
    private IMongoCollection<AuditEvent> Collection => database.GetCollection<AuditEvent>("auditLogs");

    public Task StoreAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        return Collection.InsertOneAsync(auditEvent, cancellationToken: cancellationToken);
    }

    public async Task<IEnumerable<AuditEvent>> QueryAsync(AuditLogFilter filter, CancellationToken cancellationToken = default)
    {
        var builder = Builders<AuditEvent>.Filter;
        var filters = new List<FilterDefinition<AuditEvent>>();

        if (!string.IsNullOrWhiteSpace(filter.EventType))
        {
            filters.Add(builder.Eq(x => x.EventType, filter.EventType));
        }

        if (!string.IsNullOrWhiteSpace(filter.ClientId))
        {
            filters.Add(builder.Eq(x => x.ClientId, filter.ClientId));
        }

        if (!string.IsNullOrWhiteSpace(filter.SubjectId))
        {
            filters.Add(builder.Eq(x => x.SubjectId, filter.SubjectId));
        }

        if (filter.StartTime.HasValue)
        {
            filters.Add(builder.Gte(x => x.Timestamp, filter.StartTime.Value));
        }

        if (filter.EndTime.HasValue)
        {
            filters.Add(builder.Lte(x => x.Timestamp, filter.EndTime.Value));
        }

        if (filter.Success.HasValue)
        {
            filters.Add(builder.Eq(x => x.Success, filter.Success.Value));
        }

        var combined = filters.Count > 0 ? builder.And(filters) : builder.Empty;
        IFindFluent<AuditEvent, AuditEvent> query = Collection.Find(combined).SortByDescending(x => x.Timestamp);
        if (filter.Limit is > 0)
        {
            query = query.Limit(filter.Limit.Value);
        }

        return await query.ToListAsync(cancellationToken);
    }

    public async Task PurgeOldLogsAsync(DateTime cutoff, CancellationToken cancellationToken = default)
    {
        await Collection.DeleteManyAsync(x => x.Timestamp < cutoff, cancellationToken);
    }
}
