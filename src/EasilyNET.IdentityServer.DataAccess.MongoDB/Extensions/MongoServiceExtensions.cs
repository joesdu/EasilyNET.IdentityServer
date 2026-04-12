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
        services.AddSingleton<IMongoClient>(new MongoClient(connectionString));
        services.AddSingleton(sp => sp.GetRequiredService<IMongoClient>().GetDatabase(databaseName));
        services.AddScoped<IClientStore, MongoClientStore>();
        services.AddScoped<IResourceStore, MongoResourceStore>();
        services.AddScoped<IPersistedGrantStore, MongoPersistedGrantStore>();
        services.AddScoped<IDeviceFlowStore, MongoDeviceFlowStore>();
        services.AddScoped<IUserConsentStore, MongoUserConsentStore>();
        return services;
    }
}