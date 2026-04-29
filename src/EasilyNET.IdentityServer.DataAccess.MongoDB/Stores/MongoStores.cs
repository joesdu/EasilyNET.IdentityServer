using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
using MongoDB.Driver;

namespace EasilyNET.IdentityServer.DataAccess.MongoDB.Stores;

/// <summary>
/// MongoDB 客户端存储
/// </summary>
public class MongoClientStore(IMongoDatabase database) : IClientStore
{
    private IMongoCollection<Client> Collection => database.GetCollection<Client>("clients");

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
        var entities = await Collection.Find(combined).ToListAsync(cancellationToken);
        // 过滤掉已消费的授权码，与其他存储保持一致
        return entities.Where(e => !e.ConsumedTime.HasValue);
    }

    public async Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        await Collection.DeleteOneAsync(g => g.Key == key, cancellationToken);
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
        await Collection.InsertOneAsync(deviceCode, cancellationToken: cancellationToken);
    }

    public async Task<DeviceCodeData?> FindByDeviceCodeAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(d => d.Code == deviceCode).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<DeviceCodeData?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken = default)
    {
        return await Collection.Find(d => d.UserCode == userCode).FirstOrDefaultAsync(cancellationToken);
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