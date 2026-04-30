using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.MongoDB.Stores;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;

namespace EasilyNET.IdentityServer.DataAccess.MongoDB.Extensions;

/// <summary>
/// MongoDB 数据访问层 DI 扩展
/// </summary>
public static class MongoServiceExtensions
{
    /// <summary>
    /// 添加 MongoDB 数据存储
    /// </summary>
    public static IServiceCollection AddIdentityServerMongoDB(this IServiceCollection services, string connectionString, string databaseName = "IdentityServer")
    {
        var mongoClient = new MongoClient(connectionString);
        var database = mongoClient.GetDatabase(databaseName);

        EnsureIndexes(database);

        services.AddSingleton<IMongoClient>(mongoClient);
        services.AddSingleton(database);
        services.AddScoped<IClientStore, MongoClientStore>();
        services.AddScoped<IResourceStore, MongoResourceStore>();
        services.AddScoped<IPersistedGrantStore, MongoPersistedGrantStore>();
        services.AddScoped<IDeviceFlowStore, MongoDeviceFlowStore>();
        services.AddScoped<IUserConsentStore, MongoUserConsentStore>();
        services.AddScoped<ISigningKeyStore, MongoSigningKeyStore>();
        services.AddScoped<IAuditLogStore, MongoAuditLogStore>();
        return services;
    }

    private static void EnsureIndexes(IMongoDatabase database)
    {
        database.GetCollection<Client>("clients").Indexes.CreateMany(
        [
            new CreateIndexModel<Client>(
                Builders<Client>.IndexKeys.Ascending(x => x.ClientId),
                new CreateIndexOptions { Unique = true, Name = "IX_Clients_ClientId" })
        ]);

        database.GetCollection<ApiResource>("apiResources").Indexes.CreateMany(
        [
            new CreateIndexModel<ApiResource>(
                Builders<ApiResource>.IndexKeys.Ascending(x => x.Name),
                new CreateIndexOptions { Unique = true, Name = "IX_ApiResources_Name" })
        ]);

        database.GetCollection<ApiScope>("apiScopes").Indexes.CreateMany(
        [
            new CreateIndexModel<ApiScope>(
                Builders<ApiScope>.IndexKeys.Ascending(x => x.Name),
                new CreateIndexOptions { Unique = true, Name = "IX_ApiScopes_Name" })
        ]);

        database.GetCollection<IdentityResource>("identityResources").Indexes.CreateMany(
        [
            new CreateIndexModel<IdentityResource>(
                Builders<IdentityResource>.IndexKeys.Ascending(x => x.Name),
                new CreateIndexOptions { Unique = true, Name = "IX_IdentityResources_Name" })
        ]);

        database.GetCollection<PersistedGrant>("persistedGrants").Indexes.CreateMany(
        [
            new CreateIndexModel<PersistedGrant>(
                Builders<PersistedGrant>.IndexKeys.Ascending(x => x.Key),
                new CreateIndexOptions { Unique = true, Name = "IX_PersistedGrants_Key" }),
            new CreateIndexModel<PersistedGrant>(
                Builders<PersistedGrant>.IndexKeys.Ascending(x => x.SubjectId).Ascending(x => x.ClientId).Ascending(x => x.Type),
                new CreateIndexOptions { Name = "IX_PersistedGrants_Subject_Client_Type" }),
            new CreateIndexModel<PersistedGrant>(
                Builders<PersistedGrant>.IndexKeys.Ascending(x => x.SessionId),
                new CreateIndexOptions { Name = "IX_PersistedGrants_SessionId" }),
            new CreateIndexModel<PersistedGrant>(
                Builders<PersistedGrant>.IndexKeys.Ascending(x => x.ExpirationTime),
                new CreateIndexOptions { Name = "IX_PersistedGrants_ExpirationTime" })
        ]);

        database.GetCollection<DeviceCodeData>("deviceCodes").Indexes.CreateMany(
        [
            new CreateIndexModel<DeviceCodeData>(
                Builders<DeviceCodeData>.IndexKeys.Ascending(x => x.Code),
                new CreateIndexOptions { Unique = true, Name = "IX_DeviceCodes_Code" }),
            new CreateIndexModel<DeviceCodeData>(
                Builders<DeviceCodeData>.IndexKeys.Ascending(x => x.UserCode),
                new CreateIndexOptions { Unique = true, Name = "IX_DeviceCodes_UserCode" }),
            new CreateIndexModel<DeviceCodeData>(
                Builders<DeviceCodeData>.IndexKeys.Ascending(x => x.ExpirationTime),
                new CreateIndexOptions { Name = "IX_DeviceCodes_ExpirationTime" })
        ]);

        database.GetCollection<UserConsent>("userConsents").Indexes.CreateMany(
        [
            new CreateIndexModel<UserConsent>(
                Builders<UserConsent>.IndexKeys.Ascending(x => x.SubjectId).Ascending(x => x.ClientId),
                new CreateIndexOptions { Unique = true, Name = "IX_UserConsents_Subject_Client" }),
            new CreateIndexModel<UserConsent>(
                Builders<UserConsent>.IndexKeys.Ascending(x => x.ExpirationTime),
                new CreateIndexOptions { Name = "IX_UserConsents_ExpirationTime" })
        ]);

        database.GetCollection<SigningKey>("signingKeys").Indexes.CreateMany(
        [
            new CreateIndexModel<SigningKey>(
                Builders<SigningKey>.IndexKeys.Ascending(x => x.KeyId),
                new CreateIndexOptions { Unique = true, Name = "IX_SigningKeys_KeyId" }),
            new CreateIndexModel<SigningKey>(
                Builders<SigningKey>.IndexKeys.Ascending(x => x.DisabledAt),
                new CreateIndexOptions { Name = "IX_SigningKeys_DisabledAt" })
        ]);

        database.GetCollection<AuditEvent>("auditLogs").Indexes.CreateMany(
        [
            new CreateIndexModel<AuditEvent>(
                Builders<AuditEvent>.IndexKeys.Descending(x => x.Timestamp),
                new CreateIndexOptions { Name = "IX_AuditLogs_Timestamp" }),
            new CreateIndexModel<AuditEvent>(
                Builders<AuditEvent>.IndexKeys.Ascending(x => x.ClientId).Descending(x => x.Timestamp),
                new CreateIndexOptions { Name = "IX_AuditLogs_Client_Timestamp" }),
            new CreateIndexModel<AuditEvent>(
                Builders<AuditEvent>.IndexKeys.Ascending(x => x.SubjectId).Descending(x => x.Timestamp),
                new CreateIndexOptions { Name = "IX_AuditLogs_Subject_Timestamp" }),
            new CreateIndexModel<AuditEvent>(
                Builders<AuditEvent>.IndexKeys.Ascending(x => x.EventType).Descending(x => x.Timestamp),
                new CreateIndexOptions { Name = "IX_AuditLogs_EventType_Timestamp" })
        ]);
    }
}
